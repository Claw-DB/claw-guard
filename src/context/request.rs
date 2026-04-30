#![allow(dead_code, unused_variables, unused_imports)]
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessRequest {
    pub request_id: Uuid,
    pub workspace_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    pub task_type: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_ids: Vec<String>,
    pub resource_tags: Vec<String>,
    pub session_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub risk_score_hint: f64,
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}
