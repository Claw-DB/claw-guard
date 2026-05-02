use crate::error::{GuardError, GuardResult};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ZeroizeString(pub String);

impl ZeroizeString {
    pub fn new(s: impl Into<String>) -> Self {
        ZeroizeString(s.into())
    }
}

impl std::fmt::Debug for ZeroizeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Deref for ZeroizeString {
    type Target = String;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZeroizeString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ZeroizeString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RiskThresholds {
    pub write_weight: f64,
    pub delete_weight: f64,
    pub sensitive_weight: f64,
    pub off_hours_weight: f64,
    pub deny_threshold: f64,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            write_weight: 0.25,
            delete_weight: 0.4,
            sensitive_weight: 0.35,
            off_hours_weight: 0.2,
            deny_threshold: 0.9,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardConfig {
    pub db_path: String,
    pub jwt_secret: ZeroizeString,
    pub policy_dir: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub risk_thresholds: RiskThresholds,
    pub sensitive_resources: Vec<String>,
    pub audit_flush_interval_ms: u64,
    pub audit_batch_size: usize,
}

impl GuardConfig {
    pub fn from_env() -> GuardResult<Self> {
        let db_path =
            std::env::var("CLAW_GUARD_DB_PATH").unwrap_or_else(|_| "claw_guard.db".to_owned());
        let jwt_secret = ZeroizeString::new(
            std::env::var("CLAW_GUARD_JWT_SECRET")
                .map_err(|_| GuardError::Config("CLAW_GUARD_JWT_SECRET is required".to_owned()))?,
        );
        let policy_dir = PathBuf::from(
            std::env::var("CLAW_GUARD_POLICY_DIR").unwrap_or_else(|_| "policies".to_owned()),
        );
        let tls_cert_path = PathBuf::from(
            std::env::var("CLAW_GUARD_TLS_CERT_PATH")
                .unwrap_or_else(|_| "certs/server.crt".to_owned()),
        );
        let tls_key_path = PathBuf::from(
            std::env::var("CLAW_GUARD_TLS_KEY_PATH")
                .unwrap_or_else(|_| "certs/server.key".to_owned()),
        );
        let thresholds = RiskThresholds {
            write_weight: parse_env_f64(
                "CLAW_GUARD_RISK_THRESHOLDS_WRITE_WEIGHT",
                RiskThresholds::default().write_weight,
            )?,
            delete_weight: parse_env_f64(
                "CLAW_GUARD_RISK_THRESHOLDS_DELETE_WEIGHT",
                RiskThresholds::default().delete_weight,
            )?,
            sensitive_weight: parse_env_f64(
                "CLAW_GUARD_RISK_THRESHOLDS_SENSITIVE_WEIGHT",
                RiskThresholds::default().sensitive_weight,
            )?,
            off_hours_weight: parse_env_f64(
                "CLAW_GUARD_RISK_THRESHOLDS_OFF_HOURS_WEIGHT",
                RiskThresholds::default().off_hours_weight,
            )?,
            deny_threshold: parse_env_f64(
                "CLAW_GUARD_RISK_THRESHOLDS_DENY_THRESHOLD",
                RiskThresholds::default().deny_threshold,
            )?,
        };
        let sensitive_resources = std::env::var("CLAW_GUARD_SENSITIVE_RESOURCES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_owned())
            })
            .collect();
        let audit_flush_interval_ms = parse_env_u64("CLAW_GUARD_AUDIT_FLUSH_INTERVAL_MS", 100)?;
        let audit_batch_size = parse_env_usize("CLAW_GUARD_AUDIT_BATCH_SIZE", 500)?;

        Ok(Self {
            db_path,
            jwt_secret,
            policy_dir,
            tls_cert_path,
            tls_key_path,
            risk_thresholds: thresholds,
            sensitive_resources,
            audit_flush_interval_ms,
            audit_batch_size,
        })
    }

    pub fn sqlite_connection_string(&self) -> String {
        if self.db_path.starts_with("sqlite:") {
            self.db_path.clone()
        } else {
            format!("sqlite://{}?mode=rwc", self.db_path)
        }
    }
}

fn parse_env_f64(name: &str, default: f64) -> GuardResult<f64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<f64>()
            .map_err(|error| GuardError::Config(format!("invalid {name}: {error}"))),
        Err(_) => Ok(default),
    }
}

fn parse_env_u64(name: &str, default: u64) -> GuardResult<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|error| GuardError::Config(format!("invalid {name}: {error}"))),
        Err(_) => Ok(default),
    }
}

fn parse_env_usize(name: &str, default: usize) -> GuardResult<usize> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|error| GuardError::Config(format!("invalid {name}: {error}"))),
        Err(_) => Ok(default),
    }
}
