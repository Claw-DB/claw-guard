use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use uuid::Uuid;

use crate::audit::{write_direct, AuditEntry, AuditFilter, AuditReader, AuditWriter};
use crate::config::GuardConfig;
use crate::error::GuardResult;
use crate::keys::ApiKeyManager;
use crate::masking::MaskingEngine;
use crate::policy::{EvalContext, PolicyEngine};
use crate::session::SessionManager;
use crate::types::{AccessResult, GuardSession, PolicyDecision};

/// Main public entry point for ClawDB security checks.
#[derive(Clone)]
pub struct Guard {
    pool: SqlitePool,
    keys: ApiKeyManager,
    sessions: SessionManager,
    policy: PolicyEngine,
    masking: MaskingEngine,
    audit: AuditWriter,
    audit_reader: AuditReader,
    config: Arc<GuardConfig>,
}

impl Guard {
    /// Opens the SQLite pool, applies migrations, and initializes guard services.
    pub async fn new(config: GuardConfig) -> GuardResult<Self> {
        let config = Arc::new(config);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&config.sqlite_connection_string())
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;

        let policy = PolicyEngine::new(pool.clone(), config.clone());
        if let Some(policy_dir) = &config.policy_dir {
            policy.load_from_dir(policy_dir).await?;
        }

        let audit = AuditWriter::new(
            pool.clone(),
            tokio::time::Duration::from_millis(config.audit_flush_interval_ms),
            config.audit_batch_size,
        );

        Ok(Self {
            keys: ApiKeyManager::new(pool.clone()),
            sessions: SessionManager::new(pool.clone(), config.clone()),
            policy,
            masking: MaskingEngine::new(),
            audit,
            audit_reader: AuditReader::new(pool.clone()),
            pool,
            config,
        })
    }

    /// Returns the shared API key manager.
    pub fn keys(&self) -> &ApiKeyManager {
        &self.keys
    }

    /// Returns the shared session manager.
    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Returns the policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Returns the configured masking engine.
    pub fn masking_engine(&self) -> &MaskingEngine {
        &self.masking
    }

    /// Returns the guard configuration.
    pub fn config(&self) -> &GuardConfig {
        self.config.as_ref()
    }

    /// Returns the underlying SQLite pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Evaluates a session, action, and resource triplet.
    pub async fn check_access(
        &self,
        session: &GuardSession,
        action: &str,
        resource: &str,
    ) -> GuardResult<AccessResult> {
        self.check_access_with_task(session, action, resource, action)
            .await
    }

    /// Evaluates access with an explicit task name.
    pub async fn check_access_with_task(
        &self,
        session: &GuardSession,
        action: &str,
        resource: &str,
        task: &str,
    ) -> GuardResult<AccessResult> {
        let base_entry = AuditEntry {
            id: Uuid::new_v4(),
            session_id: Some(session.id),
            workspace_id: session.workspace_id,
            agent_id: Some(session.agent_id),
            action: action.to_owned(),
            resource: resource.to_owned(),
            resource_id: None,
            decision: String::new(),
            reason: None,
            risk_score: 0.0,
            metadata: serde_json::json!({}),
            ts: Utc::now(),
        };

        match self.sessions.assert_session_active(session).await {
            Ok(()) => {
                let mut ctx = EvalContext {
                    agent_id: session.agent_id,
                    workspace_id: session.workspace_id,
                    role: session.role.clone(),
                    scopes: session.scopes.clone(),
                    task: task.to_owned(),
                    resource: resource.to_owned(),
                    action: action.to_owned(),
                    risk_score: 0.0,
                };
                ctx.risk_score = self.policy.compute_risk(&ctx);
                let decision = self.policy.evaluate(&ctx).await?;
                self.write_audit(base_entry, &decision, ctx.risk_score)
                    .await?;
                Ok(decision)
            }
            Err(error) => {
                let decision = PolicyDecision::Deny {
                    reason: error.to_string(),
                };
                self.write_audit(base_entry, &decision, 1.0).await?;
                Err(error)
            }
        }
    }

    /// Checks whether a session grants permission to use a tool.
    pub fn check_tool_permission(&self, session: &GuardSession, tool_name: &str) -> bool {
        session
            .scopes
            .iter()
            .any(|scope| scope == "tool:*" || scope == &format!("tool:{tool_name}"))
    }

    /// Queries persisted audit records.
    pub async fn query_audit(&self, filter: AuditFilter) -> GuardResult<Vec<AuditEntry>> {
        self.audit_reader.query(filter).await
    }

    async fn write_audit(
        &self,
        mut entry: AuditEntry,
        decision: &PolicyDecision,
        risk_score: f64,
    ) -> GuardResult<()> {
        match decision {
            PolicyDecision::Allow => {
                entry.decision = "Allow".to_owned();
            }
            PolicyDecision::Deny { reason } => {
                entry.decision = "Deny".to_owned();
                entry.reason = Some(reason.clone());
            }
            PolicyDecision::Mask { fields } => {
                entry.decision = "Mask".to_owned();
                entry.metadata = serde_json::json!({ "fields": fields });
            }
        }
        entry.risk_score = risk_score;

        match self.audit.write(entry.clone()).await {
            Ok(()) => Ok(()),
            Err(_) => write_direct(&self.pool, &entry).await,
        }
    }
}

#[allow(dead_code)]
fn _keep_path_used(_path: &Path) {}
