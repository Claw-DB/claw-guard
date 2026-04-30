#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{GuardError, GuardResult};
use crate::gpl::ast::{GplCondition, GplEffect, GplPolicy, GplRule};
use crate::gpl::parser::GplParser;
use crate::policy::model::{
    AccessDecision, ActionMatcher, ActionType, Policy, PolicyCondition, PolicyEffect, PolicyRule,
    ResourceMatcher, SensitivityLevel, SubjectMatcher,
};
use chrono::Weekday;
use uuid::Uuid;

pub struct GplCompiler;

impl GplCompiler {
    pub fn compile(source: &str, workspace_id: Uuid) -> GuardResult<Policy> {
        let gpl = GplParser::parse(source)?;
        let source_hash = *blake3::hash(source.as_bytes()).as_bytes();

        let rules: GuardResult<Vec<PolicyRule>> = gpl
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| Self::compile_rule(rule, i))
            .collect();

        let now = chrono::Utc::now();
        Ok(Policy {
            id: Uuid::new_v4(),
            name: gpl.name.clone(),
            version: gpl.version,
            workspace_id,
            rules: rules?,
            created_at: now,
            updated_at: now,
            is_active: true,
            description: None,
            source_hash,
        })
    }

    fn compile_rule(rule: &GplRule, idx: usize) -> GuardResult<PolicyRule> {
        let effect = Self::compile_effect(&rule.effect)?;
        let conditions: GuardResult<Vec<PolicyCondition>> = rule
            .conditions
            .iter()
            .map(Self::compile_condition)
            .collect();

        Ok(PolicyRule {
            id: Uuid::new_v4(),
            effect,
            priority: idx as i32,
            subject: SubjectMatcher::default(),
            action: ActionMatcher { action_type: ActionType::Any, tool_names: None },
            resource: ResourceMatcher::default(),
            conditions: conditions?,
            description: None,
        })
    }

    fn compile_effect(effect: &GplEffect) -> GuardResult<PolicyEffect> {
        match effect {
            GplEffect::Allow => Ok(PolicyEffect::Allow),
            GplEffect::Deny => Ok(PolicyEffect::Deny),
            GplEffect::Redact { fields } => Ok(PolicyEffect::Redact { fields: fields.clone() }),
            GplEffect::Escalate { reason } => Ok(PolicyEffect::Escalate {
                reason: reason.clone().unwrap_or_else(|| "policy escalation".into()),
            }),
            GplEffect::RateLimit { rpm } => Ok(PolicyEffect::RateLimit { requests_per_minute: *rpm }),
        }
    }

    fn compile_condition(cond: &GplCondition) -> GuardResult<PolicyCondition> {
        match cond {
            GplCondition::SubjectRole { value, negated } => {
                if *negated {
                    Ok(PolicyCondition::Not(Box::new(PolicyCondition::TaskIs {
                        task_types: vec![value.clone()],
                    })))
                } else {
                    Ok(PolicyCondition::ScopeContains { scope: format!("role:{}", value) })
                }
            }
            GplCondition::SubjectAgent { id, .. } => {
                Ok(PolicyCondition::ScopeContains { scope: format!("agent:{}", id) })
            }
            GplCondition::SubjectScope { scope } => {
                Ok(PolicyCondition::ScopeContains { scope: scope.clone() })
            }
            GplCondition::TaskIs { value, negated } => {
                let inner = PolicyCondition::TaskIs { task_types: vec![value.clone()] };
                if *negated {
                    Ok(PolicyCondition::Not(Box::new(inner)))
                } else {
                    Ok(inner)
                }
            }
            GplCondition::ResourceType { value } => {
                Ok(PolicyCondition::MetadataMatch {
                    key: "resource_type".into(),
                    value: serde_json::Value::String(value.clone()),
                })
            }
            GplCondition::ResourceSensitivity { level } => {
                Ok(PolicyCondition::MetadataMatch {
                    key: "sensitivity".into(),
                    value: serde_json::Value::String(level.to_string()),
                })
            }
            GplCondition::ResourceTag { tag } => {
                Ok(PolicyCondition::MetadataMatch {
                    key: "tags".into(),
                    value: serde_json::Value::String(tag.clone()),
                })
            }
            GplCondition::RiskBelow { threshold } => {
                Ok(PolicyCondition::RiskBelow { threshold: *threshold })
            }
            GplCondition::RiskAbove { threshold } => {
                Ok(PolicyCondition::RiskAbove { threshold: *threshold })
            }
            GplCondition::TimeBetween { start, end } => {
                Ok(PolicyCondition::TimeWindow {
                    start_hour: start.0,
                    end_hour: end.0,
                    days: vec![],
                })
            }
            GplCondition::DayIs { day } => {
                Ok(PolicyCondition::TimeWindow {
                    start_hour: 0,
                    end_hour: 24,
                    days: vec![*day],
                })
            }
            GplCondition::MetadataIs { key, value } => {
                Ok(PolicyCondition::MetadataMatch {
                    key: key.clone(),
                    value: value.clone(),
                })
            }
            GplCondition::And(conds) => {
                let compiled: GuardResult<Vec<PolicyCondition>> = conds.iter().map(Self::compile_condition).collect();
                Ok(PolicyCondition::And(compiled?))
            }
            GplCondition::Or(conds) => {
                let compiled: GuardResult<Vec<PolicyCondition>> = conds.iter().map(Self::compile_condition).collect();
                Ok(PolicyCondition::Or(compiled?))
            }
            GplCondition::Not(inner) => {
                let compiled = Self::compile_condition(inner)?;
                Ok(PolicyCondition::Not(Box::new(compiled)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws() -> Uuid { Uuid::new_v4() }

    #[test]
    fn test_compile_allow_policy() {
        let src = r#"policy "test" { allow when {} }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].effect, PolicyEffect::Allow);
    }

    #[test]
    fn test_compile_deny_policy() {
        let src = r#"policy "test" { deny when {} }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert_eq!(p.rules[0].effect, PolicyEffect::Deny);
    }

    #[test]
    fn test_compile_redact_policy() {
        let src = r#"policy "test" { redact fields ["ssn", "dob"] when {} }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert!(matches!(&p.rules[0].effect, PolicyEffect::Redact { fields } if fields.len() == 2));
    }

    #[test]
    fn test_compile_risk_condition() {
        let src = r#"policy "test" { allow when { risk below 0.7 } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        let rule = &p.rules[0];
        assert!(matches!(&rule.conditions[0], PolicyCondition::RiskBelow { threshold } if (*threshold - 0.7).abs() < f64::EPSILON));
    }

    #[test]
    fn test_compile_task_condition() {
        let src = r#"policy "test" { allow when { task is "analytics" } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert!(matches!(&p.rules[0].conditions[0], PolicyCondition::TaskIs { task_types } if task_types.contains(&"analytics".to_string())));
    }

    #[test]
    fn test_compile_scope_condition() {
        let src = r#"policy "test" { allow when { subject scope contains "read:db" } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert!(matches!(&p.rules[0].conditions[0], PolicyCondition::ScopeContains { scope } if scope == "read:db"));
    }

    #[test]
    fn test_compile_metadata_condition() {
        let src = r#"policy "test" { allow when { metadata env is "prod" } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert!(matches!(&p.rules[0].conditions[0], PolicyCondition::MetadataMatch { key, .. } if key == "env"));
    }

    #[test]
    fn test_compile_time_window_condition() {
        let src = r#"policy "test" { allow when { time between 09:00 and 17:00 } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert!(matches!(&p.rules[0].conditions[0], PolicyCondition::TimeWindow { start_hour: 9, end_hour: 17, .. }));
    }

    #[test]
    fn test_compile_source_hash() {
        let src = r#"policy "test" { allow when {} }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        let expected = *blake3::hash(src.as_bytes()).as_bytes();
        assert_eq!(p.source_hash, expected);
    }

    #[test]
    fn test_compile_workspace_id() {
        let ws_id = Uuid::new_v4();
        let src = r#"policy "test" { allow when {} }"#;
        let p = GplCompiler::compile(src, ws_id).unwrap();
        assert_eq!(p.workspace_id, ws_id);
    }

    #[test]
    fn test_compile_invalid_source() {
        let src = "not valid policy source !!!";
        assert!(GplCompiler::compile(src, ws()).is_err());
    }

    #[test]
    fn test_compile_multiple_rules() {
        let src = r#"policy "test" { allow when { risk below 0.5 } deny when { risk above 0.9 } }"#;
        let p = GplCompiler::compile(src, ws()).unwrap();
        assert_eq!(p.rules.len(), 2);
    }
}
