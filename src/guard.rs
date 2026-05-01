use std::sync::Arc;

use chrono::{Local, Timelike, Utc};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditFilter, AuditReader, AuditWriter};
use crate::config::GuardConfig;
use crate::error::GuardResult;
use crate::masking::{MaskDirective, MaskingEngine};
use crate::policy::{EvalContext, PolicyDecision, PolicyEngine};
use crate::session::{ClawSession, SessionManager};

#[derive(Debug, Clone, PartialEq)]
pub enum AccessResult {
    Allowed,
    Denied { reason: String },
    Masked { fields: Vec<MaskDirective> },
}

#[derive(Clone)]
pub struct Guard {
    config: Arc<GuardConfig>,
    pool: SqlitePool,
    pub policy_engine: PolicyEngine,
    pub session_manager: SessionManager,
    pub audit_writer: AuditWriter,
    pub audit_reader: AuditReader,
}

impl Guard {
    pub async fn new(config: GuardConfig) -> GuardResult<Self> {
        let config = Arc::new(config);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&config.sqlite_connection_string())
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;

        let policy_engine = PolicyEngine::new(pool.clone(), config.policy_dir.clone());
        let _ = policy_engine.reload_policies_from_dir().await?;
        let session_manager = SessionManager::new(pool.clone(), config.clone());
        let audit_writer = AuditWriter::new(
            pool.clone(),
            tokio::time::Duration::from_millis(config.audit_flush_interval_ms),
            config.audit_batch_size,
        );
        let audit_reader = AuditReader::new(pool.clone());

        Ok(Self {
            config,
            pool,
            policy_engine,
            session_manager,
            audit_writer,
            audit_reader,
        })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn config(&self) -> &GuardConfig {
        self.config.as_ref()
    }

    pub async fn check_access(&self, session_token: &str, action: &str, resource: &str) -> GuardResult<AccessResult> {
        self.check_access_with_task(session_token, action, resource, action).await
    }

    pub async fn check_access_with_task(
        &self,
        session_token: &str,
        action: &str,
        resource: &str,
        task: &str,
    ) -> GuardResult<AccessResult> {
        let now = Utc::now();
        let validated = self.session_manager.validate_session(session_token).await;

        let result = match validated {
            Ok(session) => {
                let risk_score = self.score_risk(action, resource);
                let context = EvalContext {
                    agent_id: session.agent_id,
                    role: session.role.clone(),
                    scopes: session.scopes.clone(),
                    task: task.to_owned(),
                    resource: resource.to_owned(),
                    risk_score,
                };
                let mut decision = self.policy_engine.evaluate(&context).await?;
                if risk_score >= self.config.risk_thresholds.deny_threshold {
                    decision = PolicyDecision::Deny {
                        reason: format!("risk score {risk_score:.2} exceeded threshold"),
                    };
                }
                let access_result = match decision {
                    PolicyDecision::Allow => AccessResult::Allowed,
                    PolicyDecision::Deny { reason } => AccessResult::Denied { reason },
                    PolicyDecision::Mask { fields } => AccessResult::Masked { fields },
                };
                self.write_audit(Some(&session), action, resource, &access_result, risk_score, now)
                    .await?;
                access_result
            }
            Err(error) => {
                let access_result = AccessResult::Denied {
                    reason: error.to_string(),
                };
                self.write_audit(None, action, resource, &access_result, 1.0, now)
                    .await?;
                return Err(error);
            }
        };

        Ok(result)
    }

    pub async fn check_tool_permission(&self, session_token: &str, tool_name: &str) -> GuardResult<bool> {
        let session = self.session_manager.validate_session(session_token).await?;
        Ok(session
            .scopes
            .iter()
            .any(|scope| scope == "tool:*" || scope == &format!("tool:{tool_name}")))
    }

    pub fn masking_engine(&self) -> MaskingEngine {
        MaskingEngine::new()
    }

    pub async fn query_audit(&self, filter: AuditFilter) -> GuardResult<Vec<AuditEntry>> {
        self.audit_reader.query(filter).await
    }

    fn score_risk(&self, action: &str, resource: &str) -> f64 {
        let mut score = 0.0;
        let action_lower = action.to_ascii_lowercase();
        if action_lower.contains("write") || action_lower.contains("update") {
            score += self.config.risk_thresholds.write_weight;
        }
        if action_lower.contains("delete") {
            score += self.config.risk_thresholds.delete_weight;
        }
        if self
            .config
            .sensitive_resources
            .iter()
            .any(|sensitive| sensitive == resource)
        {
            score += self.config.risk_thresholds.sensitive_weight;
        }
        let hour = Local::now().hour();
        if !(8..18).contains(&hour) {
            score += self.config.risk_thresholds.off_hours_weight;
        }
        score.min(1.0)
    }

    async fn write_audit(
        &self,
        session: Option<&ClawSession>,
        action: &str,
        resource: &str,
        result: &AccessResult,
        risk_score: f64,
        ts: chrono::DateTime<Utc>,
    ) -> GuardResult<()> {
        let (decision, reason) = match result {
            AccessResult::Allowed => ("allow".to_owned(), None),
            AccessResult::Denied { reason } => ("deny".to_owned(), Some(reason.clone())),
            AccessResult::Masked { fields } => (
                "mask".to_owned(),
                Some(
                    fields
                        .iter()
                        .map(|field| field.field_pattern.clone())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ),
        };
        let metadata = serde_json::json!({
            "masked_fields": match result {
                AccessResult::Masked { fields } => fields.iter().map(|field| field.field_pattern.clone()).collect::<Vec<_>>(),
                _ => Vec::<String>::new(),
            }
        });
        self.audit_writer
            .write(AuditEntry {
                id: Uuid::new_v4(),
                session_id: session.map(|item| item.session_id),
                agent_id: session.map(|item| item.agent_id).unwrap_or_else(Uuid::nil),
                action: action.to_owned(),
                resource: resource.to_owned(),
                resource_id: None,
                decision,
                reason,
                risk_score,
                metadata,
                ts,
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::config::{RiskThresholds, ZeroizeString};

    async fn setup_guard(policy_toml: &str) -> (Guard, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir should exist");
        let policy_dir = temp_dir.path().join("policies");
        fs::create_dir_all(&policy_dir).expect("policy dir should exist");
        fs::write(policy_dir.join("base.toml"), policy_toml).expect("policy should be written");
        let config = GuardConfig {
            db_path: temp_dir.path().join("guard.db").to_string_lossy().to_string(),
            jwt_secret: ZeroizeString::new("secret"),
            policy_dir: policy_dir.clone(),
            tls_cert_path: temp_dir.path().join("server.crt"),
            tls_key_path: temp_dir.path().join("server.key"),
            risk_thresholds: RiskThresholds::default(),
            sensitive_resources: vec!["finance_records".to_owned()],
            audit_flush_interval_ms: 25,
            audit_batch_size: 8,
        };
        (Guard::new(config).await.expect("guard should build"), temp_dir)
    }

    #[tokio::test]
    async fn check_access_allow_deny_and_mask() {
        let policy = r#"
name = "base"
priority = 100

[[rules]]
type = "allow_if"
condition = { role_in = ["analyst"], resource_is = "docs" }

[[rules]]
type = "deny_if"
condition = { task_matches = "scheduling", resource_is = "finance_records" }
reason = "finance blocked during scheduling"

[[rules]]
type = "mask_field"
field_pattern = "$.ssn"
mask_type = "redact"
"#;
        let (guard, _temp_dir) = setup_guard(policy).await;
        let session = guard
            .session_manager
            .create_session(Uuid::new_v4(), "analyst", vec!["tool:*".to_owned()], 120)
            .await
            .expect("session should be created");

        let allowed = guard
            .check_access_with_task(&session.token, "read", "docs", "reporting")
            .await
            .expect("allow check should succeed");
        assert_eq!(allowed, AccessResult::Allowed);

        let denied = guard
            .check_access_with_task(&session.token, "read", "finance_records", "scheduling")
            .await
            .expect("deny check should succeed");
        assert_eq!(
            denied,
            AccessResult::Denied {
                reason: "finance blocked during scheduling".to_owned()
            }
        );

        let masked = guard
            .check_access_with_task(&session.token, "read", "customers", "reporting")
            .await
            .expect("mask check should succeed");
        assert_eq!(
            masked,
            AccessResult::Masked {
                fields: vec![MaskDirective {
                    field_pattern: "$.ssn".to_owned(),
                    mask_type: crate::masking::MaskType::Redact,
                }],
            }
        );
    }
}