#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{GuardError, GuardResult};
use crate::gpl::ast::{GplCondition, GplPolicy};

pub struct GplValidator;

impl GplValidator {
    pub fn validate(policy: &GplPolicy) -> GuardResult<Vec<String>> {
        let mut warnings = Vec::new();
        for (i, rule) in policy.rules.iter().enumerate() {
            if rule.conditions.is_empty() {
                warnings.push(format!("rule {} has no conditions and will match all requests", i));
            }
            Self::check_thresholds(&rule.conditions, &mut warnings, i);
            Self::check_time_windows(&rule.conditions, &mut warnings, i);
        }
        let mut effects: Vec<String> = policy.rules.iter().map(|r| format!("{:?}", r.effect)).collect();
        let before = effects.len();
        effects.dedup();
        if effects.len() < before {
            warnings.push("policy contains rules with duplicate effects".into());
        }
        Ok(warnings)
    }

    pub fn validate_strict(policy: &GplPolicy) -> GuardResult<()> {
        let warnings = Self::validate(policy)?;
        if !warnings.is_empty() {
            return Err(GuardError::PolicyValidationError { rule_id: None, violations: warnings });
        }
        Ok(())
    }

    fn check_thresholds(conditions: &[GplCondition], warnings: &mut Vec<String>, rule_idx: usize) {
        for cond in conditions {
            match cond {
                GplCondition::RiskBelow { threshold } | GplCondition::RiskAbove { threshold } => {
                    if *threshold < 0.0 || *threshold > 1.0 {
                        warnings.push(format!("rule {}: risk threshold {} is outside [0.0, 1.0]", rule_idx, threshold));
                    }
                }
                GplCondition::And(inner) | GplCondition::Or(inner) => {
                    Self::check_thresholds(inner, warnings, rule_idx);
                }
                GplCondition::Not(inner) => {
                    Self::check_thresholds(std::slice::from_ref(inner.as_ref()), warnings, rule_idx);
                }
                _ => {}
            }
        }
    }

    fn check_time_windows(conditions: &[GplCondition], warnings: &mut Vec<String>, rule_idx: usize) {
        for cond in conditions {
            match cond {
                GplCondition::TimeBetween { start, end } => {
                    if start >= end {
                        warnings.push(format!("rule {}: time window start {:?} >= end {:?}", rule_idx, start, end));
                    }
                }
                GplCondition::And(inner) | GplCondition::Or(inner) => {
                    Self::check_time_windows(inner, warnings, rule_idx);
                }
                GplCondition::Not(inner) => {
                    Self::check_time_windows(std::slice::from_ref(inner.as_ref()), warnings, rule_idx);
                }
                _ => {}
            }
        }
    }
}
