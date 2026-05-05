use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A validated session returned by the guard engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardSession {
    /// Session identifier.
    pub id: Uuid,
    /// Agent identifier associated with the session.
    pub agent_id: Uuid,
    /// Workspace identifier associated with the session.
    pub workspace_id: Uuid,
    /// Assigned role for policy evaluation.
    pub role: String,
    /// Granted scopes for the session.
    pub scopes: Vec<String>,
    /// Expiration time of the session.
    pub expires_at: DateTime<Utc>,
    /// Signed JWT token returned to callers.
    pub token: String,
}

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The request is allowed.
    Allow,
    /// The request is denied with a reason.
    Deny { reason: String },
    /// The request is allowed only with masking directives for the listed fields.
    Mask { fields: Vec<String> },
}

/// Public alias for policy evaluation results.
pub type AccessResult = PolicyDecision;
