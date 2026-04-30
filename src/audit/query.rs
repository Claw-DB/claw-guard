#![allow(dead_code, unused_variables, unused_imports)]
use sqlx::PgPool;
use crate::audit::entry::AuditLogEntry;
use crate::error::{GuardError, GuardResult};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct AuditQueryParams {
    pub workspace_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
    pub limit: i32,
    pub cursor: Option<String>,
}

pub struct AuditQueryResult {
    pub entries: Vec<AuditLogEntry>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

pub struct AuditQueryEngine { pool: PgPool }

impl AuditQueryEngine {
    pub fn new(pool: PgPool) -> Self { Self { pool } }

    pub async fn query(&self, params: &AuditQueryParams) -> GuardResult<AuditQueryResult> {
        let rows = sqlx::query(
            "SELECT entry_json FROM audit_log WHERE workspace_id = $1 ORDER BY timestamp DESC LIMIT $2"
        )
        .bind(params.workspace_id.to_string())
        .bind(params.limit as i64)
        .fetch_all(&self.pool).await?;

        let mut entries = Vec::new();
        for row in &rows {
            use sqlx::Row;
            let json: String = row.try_get("entry_json").map_err(GuardError::Database)?;
            let entry: AuditLogEntry = serde_json::from_str(&json)?;
            entries.push(entry);
        }
        let has_more = entries.len() == params.limit as usize;
        let next_cursor = if has_more { entries.last().map(|e| e.id.to_string()) } else { None };
        Ok(AuditQueryResult { entries, next_cursor, has_more })
    }
}
