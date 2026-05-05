use std::io::Write;

use chrono::{DateTime, Utc};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, MissedTickBehavior};
use uuid::Uuid;

use crate::error::{GuardError, GuardResult};

/// A persisted audit log entry.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    /// Audit entry identifier.
    pub id: Uuid,
    /// Session identifier, when available.
    pub session_id: Option<Uuid>,
    /// Workspace identifier for the audited action.
    pub workspace_id: Uuid,
    /// Agent identifier, when available.
    pub agent_id: Option<Uuid>,
    /// Action name.
    pub action: String,
    /// Resource name.
    pub resource: String,
    /// Resource identifier, when available.
    pub resource_id: Option<String>,
    /// Decision string: `Allow`, `Deny`, or `Mask`.
    pub decision: String,
    /// Optional decision reason.
    pub reason: Option<String>,
    /// Computed risk score.
    pub risk_score: f64,
    /// Additional structured metadata.
    pub metadata: serde_json::Value,
    /// Event timestamp.
    pub ts: DateTime<Utc>,
}

/// Query filter for audit log lookups.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditFilter {
    /// Workspace identifier to filter by.
    pub workspace_id: Option<Uuid>,
    /// Session identifier to filter by.
    pub session_id: Option<Uuid>,
    /// Decision name to filter by.
    pub decision: Option<String>,
    /// Inclusive start time.
    pub start_time: Option<DateTime<Utc>>,
    /// Inclusive end time.
    pub end_time: Option<DateTime<Utc>>,
    /// Resource name to filter by.
    pub resource: Option<String>,
    /// Result limit.
    pub limit: Option<u32>,
}

/// Asynchronous audit writer that batches inserts in the background.
#[derive(Clone)]
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEntry>,
}

/// Read-only audit accessors.
#[derive(Clone)]
pub struct AuditReader {
    pool: SqlitePool,
}

impl AuditWriter {
    /// Creates a new background audit writer.
    pub fn new(pool: SqlitePool, flush_interval: Duration, batch_size: usize) -> Self {
        let batch_size = batch_size.max(1);
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(batch_size * 2);
        tokio::spawn(async move {
            let mut ticker = interval(flush_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut batch = Vec::with_capacity(batch_size);
            loop {
                tokio::select! {
                    maybe_entry = rx.recv() => {
                        match maybe_entry {
                            Some(entry) => {
                                batch.push(entry);
                                if batch.len() >= batch_size {
                                    let _ = flush_batch(&pool, &mut batch).await;
                                }
                            }
                            None => {
                                let _ = flush_batch(&pool, &mut batch).await;
                                break;
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        let _ = flush_batch(&pool, &mut batch).await;
                    }
                }
            }
        });
        Self { tx }
    }

    /// Queues an audit entry for asynchronous persistence.
    pub async fn write(&self, entry: AuditEntry) -> GuardResult<()> {
        self.tx
            .send(entry)
            .await
            .map_err(|_| GuardError::AuditChannelClosed)
    }
}

impl AuditReader {
    /// Creates a new audit reader.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Queries audit rows using the provided filter.
    pub async fn query(&self, filter: AuditFilter) -> GuardResult<Vec<AuditEntry>> {
        let mut builder = QueryBuilder::<Sqlite>::new(
            "SELECT id, session_id, workspace_id, agent_id, action, resource, resource_id, decision, reason, risk_score, metadata, ts FROM audit_log WHERE 1 = 1",
        );

        if let Some(workspace_id) = filter.workspace_id {
            builder
                .push(" AND workspace_id = ")
                .push_bind(workspace_id.to_string());
        }
        if let Some(session_id) = filter.session_id {
            builder
                .push(" AND session_id = ")
                .push_bind(session_id.to_string());
        }
        if let Some(decision) = filter.decision {
            builder.push(" AND decision = ").push_bind(decision);
        }
        if let Some(start_time) = filter.start_time {
            builder
                .push(" AND ts >= ")
                .push_bind(start_time.timestamp_millis());
        }
        if let Some(end_time) = filter.end_time {
            builder
                .push(" AND ts <= ")
                .push_bind(end_time.timestamp_millis());
        }
        if let Some(resource) = filter.resource {
            builder.push(" AND resource = ").push_bind(resource);
        }
        builder.push(" ORDER BY ts DESC");
        if let Some(limit) = filter.limit {
            builder.push(" LIMIT ").push_bind(limit as i64);
        }

        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter().map(row_to_audit_entry).collect()
    }

    /// Exports filtered audit rows as CSV.
    pub async fn export_csv(&self, filter: AuditFilter, mut writer: impl Write) -> GuardResult<()> {
        writer.write_all(b"id,session_id,workspace_id,agent_id,action,resource,resource_id,decision,reason,risk_score,ts,metadata\n")?;
        for entry in self.query(filter).await? {
            writeln!(
                writer,
                "{},{},{},{},{},{},{},{},{},{:.4},{},{}",
                csv_escape(&entry.id.to_string()),
                csv_escape(
                    &entry
                        .session_id
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                ),
                csv_escape(&entry.workspace_id.to_string()),
                csv_escape(
                    &entry
                        .agent_id
                        .map(|value| value.to_string())
                        .unwrap_or_default()
                ),
                csv_escape(&entry.action),
                csv_escape(&entry.resource),
                csv_escape(&entry.resource_id.unwrap_or_default()),
                csv_escape(&entry.decision),
                csv_escape(&entry.reason.unwrap_or_default()),
                entry.risk_score,
                csv_escape(&entry.ts.to_rfc3339()),
                csv_escape(&serde_json::to_string(&entry.metadata)?),
            )?;
        }
        Ok(())
    }
}

pub(crate) async fn write_direct(pool: &SqlitePool, entry: &AuditEntry) -> GuardResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (id, session_id, workspace_id, agent_id, action, resource, resource_id, decision, reason, risk_score, metadata, ts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )
    .bind(entry.id.to_string())
    .bind(entry.session_id.map(|value| value.to_string()))
    .bind(entry.workspace_id.to_string())
    .bind(entry.agent_id.map(|value| value.to_string()))
    .bind(&entry.action)
    .bind(&entry.resource)
    .bind(&entry.resource_id)
    .bind(&entry.decision)
    .bind(&entry.reason)
    .bind(entry.risk_score)
    .bind(serde_json::to_string(&entry.metadata)?)
    .bind(entry.ts.timestamp_millis())
    .execute(pool)
    .await?;
    Ok(())
}

async fn flush_batch(pool: &SqlitePool, batch: &mut Vec<AuditEntry>) -> GuardResult<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let pending = std::mem::take(batch);
    let mut tx = pool.begin().await?;
    for entry in &pending {
        sqlx::query(
            "INSERT INTO audit_log (id, session_id, workspace_id, agent_id, action, resource, resource_id, decision, reason, risk_score, metadata, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )
        .bind(entry.id.to_string())
        .bind(entry.session_id.map(|value| value.to_string()))
        .bind(entry.workspace_id.to_string())
        .bind(entry.agent_id.map(|value| value.to_string()))
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.resource_id)
        .bind(&entry.decision)
        .bind(&entry.reason)
        .bind(entry.risk_score)
        .bind(serde_json::to_string(&entry.metadata)?)
        .bind(entry.ts.timestamp_millis())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

fn row_to_audit_entry(row: &sqlx::sqlite::SqliteRow) -> GuardResult<AuditEntry> {
    Ok(AuditEntry {
        id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
        session_id: row
            .try_get::<Option<String>, _>("session_id")?
            .map(|value| Uuid::parse_str(&value))
            .transpose()?,
        workspace_id: Uuid::parse_str(&row.try_get::<String, _>("workspace_id")?)?,
        agent_id: row
            .try_get::<Option<String>, _>("agent_id")?
            .map(|value| Uuid::parse_str(&value))
            .transpose()?,
        action: row.try_get("action")?,
        resource: row.try_get("resource")?,
        resource_id: row.try_get("resource_id")?,
        decision: row.try_get("decision")?,
        reason: row.try_get("reason")?,
        risk_score: row.try_get("risk_score")?,
        metadata: serde_json::from_str(&row.try_get::<String, _>("metadata")?)?,
        ts: from_ms(row.try_get("ts")?)?,
    })
}

fn from_ms(value: i64) -> GuardResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(value)
        .ok_or_else(|| GuardError::ConfigError(format!("invalid timestamp millis: {value}")))
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}
