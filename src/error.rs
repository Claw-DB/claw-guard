use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("policy not found: {0}")]
    PolicyNotFound(String),
    #[error("policy parse error: {0}")]
    PolicyParse(String),
    #[error("unsupported condition shape: {0}")]
    InvalidCondition(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("invalid token: {0}")]
    TokenInvalid(String),
    #[error("token expired at {expired_at}")]
    TokenExpired { expired_at: DateTime<Utc> },
    #[error("session not found: {0}")]
    SessionNotFound(Uuid),
    #[error("session expired: {session_id} at {expired_at}")]
    SessionExpired { session_id: Uuid, expired_at: DateTime<Utc> },
    #[error("session revoked: {0}")]
    SessionRevoked(Uuid),
    #[error("audit log failed: {0}")]
    AuditLogFailed(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("uuid parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("config error: {0}")]
    Config(String),
    #[error("masking error: {0}")]
    MaskingError(String),
    #[error("transport error: {0}")]
    Transport(String),
}

impl From<GuardError> for tonic::Status {
    fn from(err: GuardError) -> Self {
        match &err {
            GuardError::AccessDenied(_) => tonic::Status::permission_denied(err.to_string()),
            GuardError::TokenInvalid(_) | GuardError::TokenExpired { .. } => tonic::Status::unauthenticated(err.to_string()),
            GuardError::PolicyNotFound(_) | GuardError::SessionNotFound(_) | GuardError::SessionRevoked(_) => tonic::Status::not_found(err.to_string()),
            GuardError::PolicyParse(_) | GuardError::InvalidCondition(_) | GuardError::Config(_) => tonic::Status::invalid_argument(err.to_string()),
            GuardError::Database(_) | GuardError::Io(_) | GuardError::Transport(_) => tonic::Status::unavailable(err.to_string()),
            _ => tonic::Status::internal(err.to_string()),
        }
    }
}

pub type GuardResult<T> = Result<T, GuardError>;
