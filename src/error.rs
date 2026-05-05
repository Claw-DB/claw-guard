use thiserror::Error;

/// Errors returned by guard operations.
#[derive(Debug, Error)]
pub enum GuardError {
    /// The supplied session token could not be verified.
    #[error("invalid token")]
    InvalidToken,
    /// The referenced session has expired.
    #[error("session expired")]
    SessionExpired,
    /// The referenced session has been revoked.
    #[error("session revoked")]
    SessionRevoked,
    /// A policy denied the attempted action.
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    /// SQLite or `sqlx` returned an error.
    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    /// Configuration was invalid or incomplete.
    #[error("config error: {0}")]
    ConfigError(String),
    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    /// File I/O failed.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// Embedded migration execution failed.
    #[error("migration error: {0}")]
    MigrationError(#[from] sqlx::migrate::MigrateError),
    /// JWT encoding or decoding failed.
    #[error("jwt error")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    /// TOML parsing failed.
    #[error("toml parse error: {0}")]
    TomlError(#[from] toml::de::Error),
    /// A UUID value could not be parsed.
    #[error("uuid parse error: {0}")]
    UuidError(#[from] uuid::Error),
    /// The audit worker channel is unavailable.
    #[error("audit channel closed")]
    AuditChannelClosed,
}

impl From<GuardError> for tonic::Status {
    fn from(value: GuardError) -> Self {
        match value {
            GuardError::InvalidToken => tonic::Status::unauthenticated("invalid token"),
            GuardError::SessionExpired | GuardError::SessionRevoked => {
                tonic::Status::unauthenticated(value.to_string())
            }
            GuardError::PolicyDenied(reason) => tonic::Status::permission_denied(reason),
            GuardError::ConfigError(message) => tonic::Status::invalid_argument(message),
            GuardError::DatabaseError(_)
            | GuardError::MigrationError(_)
            | GuardError::AuditChannelClosed => tonic::Status::unavailable(value.to_string()),
            _ => tonic::Status::internal(value.to_string()),
        }
    }
}

/// Result type used by all guard operations.
pub type GuardResult<T> = Result<T, GuardError>;
