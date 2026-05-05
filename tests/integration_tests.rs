use std::path::{Path, PathBuf};

use claw_guard::{
    AuditFilter, EvalContext, Guard, GuardConfig, GuardError, MaskDirective, MaskType,
    MaskingEngine, PolicyDecision,
};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

fn test_config(root: &Path, policy_dir: Option<PathBuf>) -> GuardConfig {
    GuardConfig {
        db_path: root.join("guard.db"),
        jwt_secret: SecretString::new("integration-secret".to_owned().into_boxed_str()),
        policy_dir,
        sensitive_resources: vec!["finance_records".to_owned()],
        audit_flush_interval_ms: 25,
        audit_batch_size: 1,
        business_hours_start_hour: 8,
        business_hours_end_hour: 18,
    }
}

async fn make_guard(policy_files: &[(&str, &str)]) -> (Guard, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let policy_dir = temp_dir.path().join("policies");
    std::fs::create_dir_all(&policy_dir).expect("policy dir");
    for (name, source) in policy_files {
        std::fs::write(policy_dir.join(name), source).expect("policy file");
    }
    let guard = Guard::new(test_config(temp_dir.path(), Some(policy_dir)))
        .await
        .expect("guard should initialize");
    (guard, temp_dir)
}

async fn wait_for_audit_rows(guard: &Guard, workspace_id: Uuid, expected: usize) {
    for _ in 0..40 {
        let rows = guard
            .query_audit(AuditFilter {
                workspace_id: Some(workspace_id),
                ..Default::default()
            })
            .await
            .expect("audit query should succeed");
        if rows.len() >= expected {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for audit rows");
}

#[tokio::test]
async fn create_validate_revoke_api_key() {
    let (guard, _tmp) = make_guard(&[]).await;
    let workspace_id = Uuid::new_v4();
    let (raw_key, record) = guard
        .keys()
        .create_key(workspace_id, "primary")
        .await
        .expect("key should be created");

    let validated = guard
        .keys()
        .validate_key(&raw_key)
        .await
        .expect("key should validate");
    assert_eq!(validated.id, record.id);

    guard
        .keys()
        .revoke_key(record.id)
        .await
        .expect("key should revoke");
    assert!(matches!(
        guard.keys().validate_key(&raw_key).await,
        Err(GuardError::InvalidToken)
    ));
}

#[tokio::test]
async fn create_validate_revoke_session() {
    let (guard, _tmp) = make_guard(&[]).await;
    let session = guard
        .sessions()
        .create_session(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "analyst",
            vec!["tool:*".to_owned()],
            300,
        )
        .await
        .expect("session should be created");

    let validated = guard
        .sessions()
        .validate_session(&session.token)
        .await
        .expect("session should validate");
    assert_eq!(validated.id, session.id);

    guard
        .sessions()
        .revoke_session(session.id)
        .await
        .expect("session should revoke");
    assert!(matches!(
        guard.sessions().validate_session(&session.token).await,
        Err(GuardError::SessionRevoked)
    ));
}

#[tokio::test]
async fn check_access_allow_writes_audit_row() {
    let allow_policy = r#"
[[policies]]
name = "allow-admin-users"
priority = 100

[[policies.rules]]
type = "allow_if"
[policies.rules.condition]
role_is = "admin"
"#;
    let (guard, _tmp) = make_guard(&[("allow.toml", allow_policy)]).await;
    let workspace_id = Uuid::new_v4();
    let session = guard
        .sessions()
        .create_session(
            Uuid::new_v4(),
            workspace_id,
            "admin",
            vec!["tool:*".to_owned()],
            300,
        )
        .await
        .expect("session should be created");

    let decision = guard
        .check_access(&session, "read", "users")
        .await
        .expect("access should succeed");
    assert_eq!(decision, PolicyDecision::Allow);

    wait_for_audit_rows(&guard, workspace_id, 1).await;
    let rows = guard
        .query_audit(AuditFilter {
            workspace_id: Some(workspace_id),
            ..Default::default()
        })
        .await
        .expect("audit query should succeed");
    assert_eq!(rows[0].decision, "Allow");
}

#[tokio::test]
async fn check_access_deny_writes_audit_row() {
    let deny_policy = r#"
[[policies]]
name = "deny-finance-during-scheduling"
priority = 100

[[policies.rules]]
type = "deny_if"
reason = "Finance data not accessible during scheduling tasks"
[policies.rules.condition]
and = [{ task_matches = "scheduling" }, { resource_is = "finance_records" }]
"#;
    let (guard, _tmp) = make_guard(&[("deny.toml", deny_policy)]).await;
    let workspace_id = Uuid::new_v4();
    let session = guard
        .sessions()
        .create_session(
            Uuid::new_v4(),
            workspace_id,
            "analyst",
            vec!["tool:*".to_owned()],
            300,
        )
        .await
        .expect("session should be created");

    let decision = guard
        .check_access_with_task(&session, "read", "finance_records", "scheduling")
        .await
        .expect("evaluation should succeed");
    assert!(matches!(
        decision,
        PolicyDecision::Deny { ref reason }
        if reason == "Finance data not accessible during scheduling tasks"
    ));

    wait_for_audit_rows(&guard, workspace_id, 1).await;
    let rows = guard
        .query_audit(AuditFilter {
            workspace_id: Some(workspace_id),
            ..Default::default()
        })
        .await
        .expect("audit query should succeed");
    assert_eq!(rows[0].decision, "Deny");
}

#[tokio::test]
async fn check_access_mask_policy_and_masking_engine() {
    let mask_policy = r#"
[[policies]]
name = "mask-users-email"
priority = 100

[[policies.rules]]
type = "mask_field"
field_pattern = "$.pii.email"
mask_type = "redact"
"#;
    let (guard, _tmp) = make_guard(&[("mask.toml", mask_policy)]).await;
    let workspace_id = Uuid::new_v4();
    let session = guard
        .sessions()
        .create_session(
            Uuid::new_v4(),
            workspace_id,
            "analyst",
            vec!["tool:*".to_owned()],
            300,
        )
        .await
        .expect("session should be created");

    let decision = guard
        .check_access(&session, "read", "users")
        .await
        .expect("evaluation should succeed");
    let fields = match decision {
        PolicyDecision::Mask { fields } => fields,
        other => panic!("expected mask decision, got {other:?}"),
    };
    assert_eq!(fields, vec!["$.pii.email".to_owned()]);

    let mut payload = json!({"pii": {"email": "alice@example.com"}});
    MaskingEngine::apply(
        &mut payload,
        &[MaskDirective {
            field_pattern: "$.pii.email".to_owned(),
            mask_type: MaskType::Redact,
        }],
    )
    .expect("masking should succeed");
    assert_eq!(payload["pii"]["email"], "[REDACTED]");

    wait_for_audit_rows(&guard, workspace_id, 1).await;
    let rows = guard
        .query_audit(AuditFilter {
            workspace_id: Some(workspace_id),
            ..Default::default()
        })
        .await
        .expect("audit query should succeed");
    assert_eq!(rows[0].decision, "Mask");
}

#[tokio::test]
async fn loads_toml_policies_from_fixture_dir() {
    let temp_dir = TempDir::new().expect("temp dir");
    let guard = Guard::new(test_config(temp_dir.path(), None))
        .await
        .expect("guard should initialize");
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("policies");

    let loaded = guard
        .policy_engine()
        .load_from_dir(&fixture_dir)
        .await
        .expect("fixture policies should load");
    assert_eq!(loaded, 1);

    let policies = guard
        .policy_engine()
        .list_policies()
        .await
        .expect("policies should list");
    assert_eq!(policies.len(), 2);

    let decision = guard
        .policy_engine()
        .evaluate(&EvalContext {
            agent_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            role: "analyst".to_owned(),
            scopes: vec!["tool:*".to_owned()],
            task: "scheduling".to_owned(),
            resource: "finance_records".to_owned(),
            action: "read".to_owned(),
            risk_score: 0.2,
        })
        .await
        .expect("evaluation should succeed");
    assert!(matches!(decision, PolicyDecision::Deny { .. }));
}
