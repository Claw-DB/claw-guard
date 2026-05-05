use std::fmt;
use std::path::PathBuf;

use secrecy::SecretString;

use crate::error::{GuardError, GuardResult};

/// Runtime configuration for the ClawDB guard engine.
#[derive(Clone)]
pub struct GuardConfig {
    /// SQLite database file path or connection string.
    pub db_path: PathBuf,
    /// HS256 secret used for signing and validating session JWTs.
    pub jwt_secret: SecretString,
    /// Optional directory containing TOML policy definitions.
    pub policy_dir: Option<PathBuf>,
    /// Sensitive resources that increase risk scores.
    pub sensitive_resources: Vec<String>,
    /// Maximum time to buffer audit entries before flushing.
    pub audit_flush_interval_ms: u64,
    /// Maximum number of buffered audit entries per flush.
    pub audit_batch_size: usize,
    /// Inclusive start of business hours in local time.
    pub business_hours_start_hour: u8,
    /// Exclusive end of business hours in local time.
    pub business_hours_end_hour: u8,
}

impl fmt::Debug for GuardConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardConfig")
            .field("db_path", &self.db_path)
            .field("jwt_secret", &"***REDACTED***")
            .field("policy_dir", &self.policy_dir)
            .field("sensitive_resources", &self.sensitive_resources)
            .field("audit_flush_interval_ms", &self.audit_flush_interval_ms)
            .field("audit_batch_size", &self.audit_batch_size)
            .field("business_hours_start_hour", &self.business_hours_start_hour)
            .field("business_hours_end_hour", &self.business_hours_end_hour)
            .finish()
    }
}

impl GuardConfig {
    /// Builds configuration from `CLAW_GUARD_*` environment variables.
    pub fn from_env() -> GuardResult<Self> {
        let jwt_secret = std::env::var("CLAW_GUARD_JWT_SECRET")
            .map(|value| SecretString::new(value.into_boxed_str()))
            .map_err(|_| GuardError::ConfigError("CLAW_GUARD_JWT_SECRET is required".to_owned()))?;
        let db_path = std::env::var("CLAW_GUARD_DB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("claw_guard.db"));
        let policy_dir = std::env::var("CLAW_GUARD_POLICY_DIR")
            .ok()
            .map(PathBuf::from)
            .filter(|value| !value.as_os_str().is_empty());
        let sensitive_resources = std::env::var("CLAW_GUARD_SENSITIVE_RESOURCES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_owned())
            })
            .collect();

        Ok(Self {
            db_path,
            jwt_secret,
            policy_dir,
            sensitive_resources,
            audit_flush_interval_ms: parse_or_default("CLAW_GUARD_AUDIT_FLUSH_INTERVAL_MS", 100)?,
            audit_batch_size: parse_or_default("CLAW_GUARD_AUDIT_BATCH_SIZE", 500)?,
            business_hours_start_hour: parse_or_default("CLAW_GUARD_BUSINESS_HOURS_START", 8)?,
            business_hours_end_hour: parse_or_default("CLAW_GUARD_BUSINESS_HOURS_END", 18)?,
        })
    }

    /// Returns a SQLite connection string for `sqlx`.
    pub fn sqlite_connection_string(&self) -> String {
        let path = self.db_path.to_string_lossy();
        if path == ":memory:" {
            "sqlite::memory:".to_owned()
        } else if path.starts_with("sqlite:") {
            path.into_owned()
        } else {
            format!("sqlite://{}?mode=rwc", path)
        }
    }
}

fn parse_or_default<T>(name: &str, default: T) -> GuardResult<T>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse::<T>()
            .map_err(|error| GuardError::ConfigError(format!("invalid {name}: {error}"))),
        Err(_) => Ok(default),
    }
}
