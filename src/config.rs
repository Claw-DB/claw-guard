#![allow(dead_code, unused_variables, unused_imports)]
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroize;
use crate::error::{GuardError, GuardResult};

#[derive(Clone, Default)]
pub struct ZeroizeString(pub String);

impl ZeroizeString {
    pub fn new(s: impl Into<String>) -> Self { ZeroizeString(s.into()) }
}

impl std::fmt::Debug for ZeroizeString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("[REDACTED]") }
}

impl Deref for ZeroizeString {
    type Target = String;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for ZeroizeString {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Drop for ZeroizeString {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub database_url: String,
    pub workspace_id: Uuid,
    pub jwt_secret: ZeroizeString,
    pub jwt_issuer: String,
    pub jwt_audience: Vec<String>,
    pub oauth_introspection_url: Option<String>,
    pub session_ttl_secs: u64,
    pub policy_cache_ttl_secs: u64,
    pub policy_hot_reload: bool,
    pub default_deny: bool,
    pub risk_high_threshold: f64,
    pub risk_critical_threshold: f64,
    pub max_rules_per_policy: usize,
    pub audit_log_enabled: bool,
    pub audit_signing_enabled: bool,
    pub webhook_timeout_ms: u64,
    pub grpc_port: u16,
    pub data_dir: PathBuf,
}

impl GuardConfig {
    pub fn builder() -> GuardConfigBuilder { GuardConfigBuilder::default() }

    pub fn from_env() -> GuardResult<Self> {
        let mut builder = GuardConfigBuilder::default();
        if let Ok(v) = std::env::var("CLAW_GUARD_DATABASE_URL") { builder = builder.database_url(v); }
        if let Ok(v) = std::env::var("CLAW_GUARD_WORKSPACE_ID") {
            let id = v.parse::<Uuid>().map_err(|e| GuardError::Config(format!("invalid CLAW_GUARD_WORKSPACE_ID: {e}")))?;
            builder = builder.workspace_id(id);
        }
        if let Ok(v) = std::env::var("CLAW_GUARD_JWT_SECRET") { builder = builder.jwt_secret(ZeroizeString::new(v)); }
        if let Ok(v) = std::env::var("CLAW_GUARD_JWT_ISSUER") { builder = builder.jwt_issuer(v); }
        if let Ok(v) = std::env::var("CLAW_GUARD_JWT_AUDIENCE") { builder = builder.jwt_audience(v.split(',').map(|s| s.trim().to_owned()).collect()); }
        if let Ok(v) = std::env::var("CLAW_GUARD_OAUTH_INTROSPECT_URL") { builder = builder.oauth_introspection_url(Some(v)); }
        if let Ok(v) = std::env::var("CLAW_GUARD_SESSION_TTL") {
            let n: u64 = v.parse().map_err(|e| GuardError::Config(format!("invalid CLAW_GUARD_SESSION_TTL: {e}")))?;
            builder = builder.session_ttl_secs(n);
        }
        if let Ok(v) = std::env::var("CLAW_GUARD_POLICY_CACHE_TTL") {
            let n: u64 = v.parse().map_err(|e| GuardError::Config(format!("invalid CLAW_GUARD_POLICY_CACHE_TTL: {e}")))?;
            builder = builder.policy_cache_ttl_secs(n);
        }
        if let Ok(v) = std::env::var("CLAW_GUARD_HOT_RELOAD") { builder = builder.policy_hot_reload(v == "true" || v == "1"); }
        if let Ok(v) = std::env::var("CLAW_GUARD_DEFAULT_DENY") { builder = builder.default_deny(v == "true" || v == "1"); }
        if let Ok(v) = std::env::var("CLAW_GUARD_DATA_DIR") { builder = builder.data_dir(PathBuf::from(v)); }
        builder.build()
    }
}

#[derive(Debug, Default)]
pub struct GuardConfigBuilder {
    database_url: Option<String>,
    workspace_id: Option<Uuid>,
    jwt_secret: Option<ZeroizeString>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<Vec<String>>,
    oauth_introspection_url: Option<Option<String>>,
    session_ttl_secs: Option<u64>,
    policy_cache_ttl_secs: Option<u64>,
    policy_hot_reload: Option<bool>,
    default_deny: Option<bool>,
    risk_high_threshold: Option<f64>,
    risk_critical_threshold: Option<f64>,
    max_rules_per_policy: Option<usize>,
    audit_log_enabled: Option<bool>,
    audit_signing_enabled: Option<bool>,
    webhook_timeout_ms: Option<u64>,
    grpc_port: Option<u16>,
    data_dir: Option<PathBuf>,
}

impl GuardConfigBuilder {
    pub fn database_url(mut self, v: impl Into<String>) -> Self { self.database_url = Some(v.into()); self }
    pub fn workspace_id(mut self, v: Uuid) -> Self { self.workspace_id = Some(v); self }
    pub fn jwt_secret(mut self, v: ZeroizeString) -> Self { self.jwt_secret = Some(v); self }
    pub fn jwt_issuer(mut self, v: impl Into<String>) -> Self { self.jwt_issuer = Some(v.into()); self }
    pub fn jwt_audience(mut self, v: Vec<String>) -> Self { self.jwt_audience = Some(v); self }
    pub fn oauth_introspection_url(mut self, v: Option<String>) -> Self { self.oauth_introspection_url = Some(v); self }
    pub fn session_ttl_secs(mut self, v: u64) -> Self { self.session_ttl_secs = Some(v); self }
    pub fn policy_cache_ttl_secs(mut self, v: u64) -> Self { self.policy_cache_ttl_secs = Some(v); self }
    pub fn policy_hot_reload(mut self, v: bool) -> Self { self.policy_hot_reload = Some(v); self }
    pub fn default_deny(mut self, v: bool) -> Self { self.default_deny = Some(v); self }
    pub fn risk_high_threshold(mut self, v: f64) -> Self { self.risk_high_threshold = Some(v); self }
    pub fn risk_critical_threshold(mut self, v: f64) -> Self { self.risk_critical_threshold = Some(v); self }
    pub fn max_rules_per_policy(mut self, v: usize) -> Self { self.max_rules_per_policy = Some(v); self }
    pub fn audit_log_enabled(mut self, v: bool) -> Self { self.audit_log_enabled = Some(v); self }
    pub fn audit_signing_enabled(mut self, v: bool) -> Self { self.audit_signing_enabled = Some(v); self }
    pub fn webhook_timeout_ms(mut self, v: u64) -> Self { self.webhook_timeout_ms = Some(v); self }
    pub fn grpc_port(mut self, v: u16) -> Self { self.grpc_port = Some(v); self }
    pub fn data_dir(mut self, v: PathBuf) -> Self { self.data_dir = Some(v); self }

    pub fn build(self) -> GuardResult<GuardConfig> {
        let jwt_secret = self.jwt_secret.unwrap_or_default();
        if jwt_secret.is_empty() {
            return Err(GuardError::Config("jwt_secret must not be empty".into()));
        }
        let workspace_id = self.workspace_id.unwrap_or(Uuid::nil());
        if workspace_id.is_nil() {
            return Err(GuardError::Config("workspace_id must be a non-nil UUID".into()));
        }
        let risk_high = self.risk_high_threshold.unwrap_or(0.8);
        let risk_critical = self.risk_critical_threshold.unwrap_or(0.95);
        if risk_high >= risk_critical {
            return Err(GuardError::Config("risk_high_threshold must be strictly less than risk_critical_threshold".into()));
        }
        Ok(GuardConfig {
            database_url: self.database_url.unwrap_or_default(),
            workspace_id,
            jwt_secret,
            jwt_issuer: self.jwt_issuer.unwrap_or_default(),
            jwt_audience: self.jwt_audience.unwrap_or_default(),
            oauth_introspection_url: self.oauth_introspection_url.unwrap_or(None),
            session_ttl_secs: self.session_ttl_secs.unwrap_or(3600),
            policy_cache_ttl_secs: self.policy_cache_ttl_secs.unwrap_or(60),
            policy_hot_reload: self.policy_hot_reload.unwrap_or(true),
            default_deny: self.default_deny.unwrap_or(true),
            risk_high_threshold: risk_high,
            risk_critical_threshold: risk_critical,
            max_rules_per_policy: self.max_rules_per_policy.unwrap_or(500),
            audit_log_enabled: self.audit_log_enabled.unwrap_or(true),
            audit_signing_enabled: self.audit_signing_enabled.unwrap_or(true),
            webhook_timeout_ms: self.webhook_timeout_ms.unwrap_or(5000),
            grpc_port: self.grpc_port.unwrap_or(50052),
            data_dir: self.data_dir.unwrap_or_else(|| PathBuf::from("/var/lib/claw-guard")),
        })
    }
}
