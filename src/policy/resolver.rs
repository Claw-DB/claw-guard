#![allow(dead_code, unused_variables, unused_imports)]
use crate::config::GuardConfig;
use crate::error::{GuardError, GuardResult};
use crate::policy::model::{AccessDecision, PolicyEffect, PolicyRule};
use std::sync::Arc;
use uuid::Uuid;

pub struct ConflictResolver {
    config: Arc<GuardConfig>,
}

impl ConflictResolver {
    pub fn new(config: Arc<GuardConfig>) -> Self {
        Self { config }
    }

    pub fn resolve(&self, rules: Vec<&PolicyRule>) -> GuardResult<AccessDecision> {
        // Deny-override: any matching Deny rule takes precedence
        for rule in &rules {
            if matches!(rule.effect, PolicyEffect::Deny) {
                return Ok(AccessDecision::Deny {
                    reason: rule.description.clone().unwrap_or_else(|| "policy deny rule matched".into()),
                    rule_id: Some(rule.id),
                });
            }
        }

        // Then check for other effects
        for rule in &rules {
            match &rule.effect {
                PolicyEffect::Allow => return Ok(AccessDecision::Allow),
                PolicyEffect::Redact { fields } => {
                    return Ok(AccessDecision::Redact {
                        fields: fields.clone(),
                        reason: rule.description.clone().unwrap_or_else(|| "policy redact rule matched".into()),
                    });
                }
                PolicyEffect::Escalate { reason } => {
                    return Ok(AccessDecision::Escalate { reason: reason.clone() });
                }
                PolicyEffect::RateLimit { requests_per_minute } => {
                    let retry_after_ms = 60_000 / (*requests_per_minute as u64).max(1);
                    return Ok(AccessDecision::RateLimit { retry_after_ms });
                }
                PolicyEffect::Deny => unreachable!(),
            }
        }

        if self.config.default_deny {
            Ok(AccessDecision::Deny {
                reason: "default deny".into(),
                rule_id: None,
            })
        } else {
            Ok(AccessDecision::Allow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZeroizeString;
    use crate::policy::model::{ActionMatcher, ActionType, ResourceMatcher, SubjectMatcher};
    use uuid::Uuid;

    fn make_config() -> Arc<GuardConfig> {
        Arc::new(GuardConfig {
            database_url: String::new(),
            workspace_id: Uuid::new_v4(),
            jwt_secret: ZeroizeString::new("test-secret-key-long-enough"),
            jwt_issuer: "test".into(),
            jwt_audience: vec![],
            oauth_introspection_url: None,
            session_ttl_secs: 3600,
            policy_cache_ttl_secs: 60,
            policy_hot_reload: false,
            default_deny: true,
            risk_high_threshold: 0.8,
            risk_critical_threshold: 0.95,
            max_rules_per_policy: 500,
            audit_log_enabled: false,
            audit_signing_enabled: false,
            webhook_timeout_ms: 5000,
            grpc_port: 50052,
            data_dir: std::path::PathBuf::from("/tmp"),
        })
    }

    fn make_rule(effect: PolicyEffect, priority: i32) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            effect,
            priority,
            subject: SubjectMatcher::default(),
            action: ActionMatcher { action_type: ActionType::Any, tool_names: None },
            resource: ResourceMatcher::default(),
            conditions: vec![],
            description: None,
        }
    }

    #[test]
    fn test_deny_overrides_allow() {
        let resolver = ConflictResolver::new(make_config());
        let allow_rule = make_rule(PolicyEffect::Allow, 10);
        let deny_rule = make_rule(PolicyEffect::Deny, 5);
        let rules = vec![&deny_rule, &allow_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::Deny { .. }));
    }

    #[test]
    fn test_allow_when_no_deny() {
        let resolver = ConflictResolver::new(make_config());
        let allow_rule = make_rule(PolicyEffect::Allow, 10);
        let rules = vec![&allow_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::Allow));
    }

    #[test]
    fn test_redact_effect() {
        let resolver = ConflictResolver::new(make_config());
        let redact_rule = make_rule(PolicyEffect::Redact { fields: vec!["ssn".into()] }, 10);
        let rules = vec![&redact_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::Redact { .. }));
    }

    #[test]
    fn test_escalate_effect() {
        let resolver = ConflictResolver::new(make_config());
        let esc_rule = make_rule(PolicyEffect::Escalate { reason: "needs review".into() }, 10);
        let rules = vec![&esc_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::Escalate { .. }));
    }

    #[test]
    fn test_rate_limit_effect() {
        let resolver = ConflictResolver::new(make_config());
        let rl_rule = make_rule(PolicyEffect::RateLimit { requests_per_minute: 60 }, 10);
        let rules = vec![&rl_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::RateLimit { retry_after_ms: 1000 }));
    }

    #[test]
    fn test_empty_rules_default_deny() {
        let resolver = ConflictResolver::new(make_config());
        let decision = resolver.resolve(vec![]).unwrap();
        assert!(matches!(decision, AccessDecision::Deny { .. }));
    }

    #[test]
    fn test_deny_with_rule_id() {
        let resolver = ConflictResolver::new(make_config());
        let rule_id = Uuid::new_v4();
        let deny_rule = PolicyRule {
            id: rule_id,
            effect: PolicyEffect::Deny,
            priority: 0,
            subject: SubjectMatcher::default(),
            action: ActionMatcher { action_type: ActionType::Any, tool_names: None },
            resource: ResourceMatcher::default(),
            conditions: vec![],
            description: Some("test deny".into()),
        };
        let rules = vec![&deny_rule];
        let decision = resolver.resolve(rules).unwrap();
        assert!(matches!(decision, AccessDecision::Deny { rule_id: Some(id), .. } if id == rule_id));
    }

    #[test]
    fn test_priority_order_deny_bonus() {
        let allow_rule = make_rule(PolicyEffect::Allow, 5);
        let deny_rule = make_rule(PolicyEffect::Deny, 5);
        assert!(deny_rule.priority_order() > allow_rule.priority_order());
    }

    #[test]
    fn test_higher_priority_wins() {
        let low = make_rule(PolicyEffect::Allow, 1);
        let high = make_rule(PolicyEffect::Allow, 10);
        assert!(high.priority_order() > low.priority_order());
    }

    #[test]
    fn test_rate_limit_retry_calculation() {
        let resolver = ConflictResolver::new(make_config());
        let rl_rule = make_rule(PolicyEffect::RateLimit { requests_per_minute: 30 }, 10);
        let decision = resolver.resolve(vec![&rl_rule]).unwrap();
        assert!(matches!(decision, AccessDecision::RateLimit { retry_after_ms: 2000 }));
    }

    #[test]
    fn test_deny_takes_precedence_over_redact() {
        let resolver = ConflictResolver::new(make_config());
        let deny_rule = make_rule(PolicyEffect::Deny, 5);
        let redact_rule = make_rule(PolicyEffect::Redact { fields: vec!["x".into()] }, 10);
        let decision = resolver.resolve(vec![&deny_rule, &redact_rule]).unwrap();
        assert!(matches!(decision, AccessDecision::Deny { .. }));
    }

    #[test]
    fn test_is_permitted_allow() {
        assert!(AccessDecision::Allow.is_permitted());
    }

    #[test]
    fn test_is_permitted_deny() {
        assert!(!AccessDecision::Deny { reason: "x".into(), rule_id: None }.is_permitted());
    }
}
