#![allow(dead_code, unused_variables, unused_imports)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyVersion {
    pub policy_id: Uuid,
    pub version: u32,
    pub source_hash: [u8; 32],
    pub created_at: DateTime<Utc>,
    pub author: Option<String>,
    pub changelog: Option<String>,
}

impl PolicyVersion {
    pub fn new(policy_id: Uuid, version: u32, source_hash: [u8; 32]) -> Self {
        Self {
            policy_id,
            version,
            source_hash,
            created_at: Utc::now(),
            author: None,
            changelog: None,
        }
    }
}
