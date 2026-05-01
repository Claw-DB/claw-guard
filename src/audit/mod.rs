use std::io::Write;

use chrono::{DateTime, Utc};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::error::{GuardError, GuardResult};

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
	pub id: Uuid,
	pub session_id: Option<Uuid>,
	pub agent_id: Uuid,
	pub action: String,
	pub resource: String,
	pub resource_id: Option<String>,
	pub decision: String,
	pub reason: Option<String>,
	pub risk_score: f64,
	pub metadata: serde_json::Value,
	pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuditFilter {
	pub session_id: Option<Uuid>,
	pub agent_id: Option<Uuid>,
	pub decision: Option<String>,
	pub start_time: Option<DateTime<Utc>>,
	pub end_time: Option<DateTime<Utc>>,
	pub resource: Option<String>,
	pub limit: Option<u32>,
}

#[derive(Clone)]
pub struct AuditWriter {
	tx: mpsc::Sender<AuditEntry>,
}

#[derive(Clone)]
pub struct AuditReader {
	pool: SqlitePool,
}

impl AuditWriter {
	pub fn new(pool: SqlitePool, flush_interval: Duration, batch_size: usize) -> Self {
		let (tx, mut rx) = mpsc::channel::<AuditEntry>(batch_size.saturating_mul(2));
		tokio::spawn(async move {
			let mut ticker = interval(flush_interval);
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

	pub async fn write(&self, entry: AuditEntry) -> GuardResult<()> {
		self.tx
			.send(entry)
			.await
			.map_err(|error| GuardError::AuditLogFailed(error.to_string()))
	}
}

impl AuditReader {
	pub fn new(pool: SqlitePool) -> Self {
		Self { pool }
	}

	pub async fn query(&self, filter: AuditFilter) -> GuardResult<Vec<AuditEntry>> {
		let mut builder = QueryBuilder::<Sqlite>::new(
			"SELECT id, session_id, agent_id, action, resource, resource_id, decision, reason, risk_score, metadata, ts FROM audit_log WHERE 1 = 1",
		);

		if let Some(session_id) = filter.session_id {
			builder.push(" AND session_id = ").push_bind(session_id.to_string());
		}
		if let Some(agent_id) = filter.agent_id {
			builder.push(" AND agent_id = ").push_bind(agent_id.to_string());
		}
		if let Some(decision) = filter.decision {
			builder.push(" AND decision = ").push_bind(decision);
		}
		if let Some(start) = filter.start_time {
			builder.push(" AND ts >= ").push_bind(start);
		}
		if let Some(end) = filter.end_time {
			builder.push(" AND ts <= ").push_bind(end);
		}
		if let Some(resource) = filter.resource {
			builder.push(" AND resource = ").push_bind(resource);
		}
		builder.push(" ORDER BY ts DESC");
		if let Some(limit) = filter.limit {
			builder.push(" LIMIT ").push_bind(limit as i64);
		}

		let rows = builder.build().fetch_all(&self.pool).await?;
		rows.into_iter().map(row_to_audit_entry).collect()
	}

	pub async fn export_csv(&self, filter: AuditFilter, mut writer: impl Write) -> GuardResult<()> {
		writer.write_all(b"id,session_id,agent_id,action,resource,resource_id,decision,reason,risk_score,ts,metadata\n")?;
		for entry in self.query(filter).await? {
			writeln!(
				writer,
				"{},{},{},{},{},{},{},{},{:.4},{},{}",
				csv_escape(&entry.id.to_string()),
				csv_escape(&entry.session_id.map(|value| value.to_string()).unwrap_or_default()),
				csv_escape(&entry.agent_id.to_string()),
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

async fn flush_batch(pool: &SqlitePool, batch: &mut Vec<AuditEntry>) -> GuardResult<()> {
	if batch.is_empty() {
		return Ok(());
	}

	let pending = std::mem::take(batch);
	let mut tx = pool.begin().await?;
	for entry in pending {
		sqlx::query(
			"INSERT INTO audit_log (id, session_id, agent_id, action, resource, resource_id, decision, reason, risk_score, metadata, ts)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
		)
		.bind(entry.id.to_string())
		.bind(entry.session_id.map(|value| value.to_string()))
		.bind(entry.agent_id.to_string())
		.bind(entry.action)
		.bind(entry.resource)
		.bind(entry.resource_id)
		.bind(entry.decision)
		.bind(entry.reason)
		.bind(entry.risk_score)
		.bind(serde_json::to_string(&entry.metadata)?)
		.bind(entry.ts)
		.execute(&mut *tx)
		.await?;
	}
	tx.commit().await?;
	Ok(())
}

fn row_to_audit_entry(row: sqlx::sqlite::SqliteRow) -> GuardResult<AuditEntry> {
	let id: String = row.try_get("id")?;
	let session_id: Option<String> = row.try_get("session_id")?;
	let agent_id: String = row.try_get("agent_id")?;
	let metadata: String = row.try_get("metadata")?;
	Ok(AuditEntry {
		id: Uuid::parse_str(&id)?,
		session_id: session_id.map(|value| Uuid::parse_str(&value)).transpose()?,
		agent_id: Uuid::parse_str(&agent_id)?,
		action: row.try_get("action")?,
		resource: row.try_get("resource")?,
		resource_id: row.try_get("resource_id")?,
		decision: row.try_get("decision")?,
		reason: row.try_get("reason")?,
		risk_score: row.try_get("risk_score")?,
		metadata: serde_json::from_str(&metadata)?,
		ts: row.try_get("ts")?,
	})
}

fn csv_escape(value: &str) -> String {
	if value.contains(',') || value.contains('"') || value.contains('\n') {
		format!("\"{}\"", value.replace('"', "\"\""))
	} else {
		value.to_owned()
	}
}
