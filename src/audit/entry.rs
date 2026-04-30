#![allow(dead_code, unused_variables, unused_imports)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub workspace_id: Uuid,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_ids: Vec<String>,
    pub decision: String,
    pub risk_score: f64,
    pub rule_id_matched: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub sequence: u64,
    pub signature: Option<Vec<u8>>,
    pub prev_hash: Option<[u8; 32]>,
}

impl AuditLogEntry {
    pub fn content_bytes(&self) -> Vec<u8> {
        let s = format!("{}:{}:{}:{}:{}", self.id, self.agent_id, self.action, self.decision, self.timestamp.timestamp());
        s.into_bytes()
    }
}
