#![allow(dead_code, unused_variables, unused_imports)]
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("policy not found: {0}")]
    PolicyNotFound(Uuid),
    #[error("policy parse error at {line}:{column}: {message}")]
    PolicyParseError { source_text: String, line: usize, column: usize, message: String },
    #[error("policy validation error: {violations:?}")]
    PolicyValidationError { rule_id: Option<Uuid>, violations: Vec<String> },
    #[error("policy conflict between rules {rule_a} and {rule_b} on resource {resource}")]
    PolicyConflict { rule_a: Uuid, rule_b: Uuid, resource: String },
    #[error("access denied: {subject} cannot {action} on {resource}: {reason}")]
    AccessDenied { subject: String, action: String, resource: String, reason: String },
    #[error("invalid token: {0}")]
    TokenInvalid(String),
    #[error("token expired at {expired_at}")]
    TokenExpired { expired_at: DateTime<Utc> },
    #[error("insufficient scope: required {required}, present {present:?}")]
    InsufficientScope { required: String, present: Vec<String> },
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),
    #[error("session expired: {0}")]
    SessionExpired(Uuid),
    #[error("risk threshold exceeded: score {score} >= threshold {threshold} (action: {action})")]
    RiskThresholdExceeded { score: f64, threshold: f64, action: String },
    #[error("audit log failed: {0}")]
    AuditLogFailed(String),
    #[error("audit chain broken at sequence {at_sequence}")]
    AuditChainBroken { at_sequence: u64 },
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("webhook delivery failed to {url} after {attempts} attempts")]
    WebhookDeliveryFailed { url: String, attempts: u32 },
    #[error("SCIM error: {0}")]
    ScimError(String),
    #[error("SAML error: {0}")]
    SamlError(String),
    #[error("GPL parse error: {0}")]
    GplParseError(String),
    #[error("masking error: {0}")]
    MaskingError(String),
}

impl GuardError {
    pub fn is_access_denied(&self) -> bool {
        matches!(self, GuardError::AccessDenied { .. })
    }
    pub fn is_auth_error(&self) -> bool {
        matches!(self, GuardError::TokenInvalid(_) | GuardError::TokenExpired { .. } | GuardError::InsufficientScope { .. } | GuardError::SessionNotFound(_) | GuardError::SessionExpired(_))
    }
    pub fn is_policy_error(&self) -> bool {
        matches!(self, GuardError::PolicyNotFound(_) | GuardError::PolicyParseError { .. } | GuardError::PolicyValidationError { .. } | GuardError::PolicyConflict { .. } | GuardError::GplParseError(_))
    }
    pub fn is_retryable(&self) -> bool {
        matches!(self, GuardError::Database(_) | GuardError::WebhookDeliveryFailed { .. })
    }
}

impl From<GuardError> for tonic::Status {
    fn from(err: GuardError) -> Self {
        match &err {
            GuardError::AccessDenied { .. } => tonic::Status::permission_denied(err.to_string()),
            GuardError::TokenInvalid(_) | GuardError::TokenExpired { .. } | GuardError::InsufficientScope { .. } => tonic::Status::unauthenticated(err.to_string()),
            GuardError::PolicyNotFound(_) | GuardError::SessionNotFound(_) => tonic::Status::not_found(err.to_string()),
            GuardError::PolicyValidationError { .. } | GuardError::PolicyParseError { .. } | GuardError::GplParseError(_) => tonic::Status::invalid_argument(err.to_string()),
            GuardError::Database(_) | GuardError::Io(_) => tonic::Status::unavailable(err.to_string()),
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

pub type GuardResult<T> = Result<T, GuardError>;
