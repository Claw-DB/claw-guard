#![allow(dead_code, unused_variables, unused_imports)]
use sqlx::PgPool;
use crate::audit::entry::AuditLogEntry;
use crate::error::{GuardError, GuardResult};
use chrono::Utc;
use uuid::Uuid;

pub struct AuditLog { pool: PgPool }

impl AuditLog {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    pub async fn append(&self, entry: &AuditLogEntry) -> GuardResult<()> {
        let json = serde_json::to_string(entry)?;
        sqlx::query(
            "INSERT INTO audit_log (id, workspace_id, agent_id, action, decision, risk_score, timestamp, entry_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)"
        )
        .bind(entry.id.to_string())
        .bind(entry.workspace_id.to_string())
        .bind(entry.agent_id.to_string())
        .bind(&entry.action)
        .bind(&entry.decision)
        .bind(entry.risk_score)
        .bind(entry.timestamp)
        .bind(&json)
        .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn latest_sequence(&self, workspace_id: Uuid) -> GuardResult<u64> {
        let row = sqlx::query("SELECT COALESCE(MAX(sequence_num), 0) as seq FROM audit_log WHERE workspace_id = $1")
            .bind(workspace_id.to_string())
            .fetch_one(&self.pool).await?;
        use sqlx::Row;
        let seq: i64 = row.try_get("seq").unwrap_or(0);
        Ok(seq as u64)
    }
}
