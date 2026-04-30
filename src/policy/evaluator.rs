#![allow(dead_code, unused_variables, unused_imports)]
use crate::context::EvaluationContext;
use crate::error::{GuardError, GuardResult};
use crate::policy::model::{AccessDecision, Policy, PolicyCondition, PolicyEffect, PolicyRule};
use crate::policy::resolver::ConflictResolver;
use crate::policy::store::PolicyStore;
use std::sync::Arc;
use uuid::Uuid;

pub struct PolicyEvaluator {
    store: Arc<PolicyStore>,
    resolver: ConflictResolver,
}

impl PolicyEvaluator {
    pub fn new(store: Arc<PolicyStore>, resolver: ConflictResolver) -> Self {
        Self { store, resolver }
    }

    pub async fn evaluate(&self, ctx: &EvaluationContext) -> GuardResult<AccessDecision> {
        let policies = self.store.get_active(ctx.request.workspace_id).await?;

        let mut matching_rules: Vec<&PolicyRule> = policies
            .iter()
            .flat_map(|p| p.rules.iter())
            .filter(|r| {
                r.matches(&ctx.request)
                    && r.conditions.iter().all(|c| c.evaluate(ctx))
            })
            .collect();

        matching_rules.sort_by(|a, b| {
            b.priority_order().cmp(&a.priority_order())
        });

        if matching_rules.is_empty() {
            if self.store.config.default_deny {
                return Ok(AccessDecision::Deny {
                    reason: "no matching policy rule (default deny)".into(),
                    rule_id: None,
                });
            }
            return Ok(AccessDecision::Allow);
        }

        let decision = self.resolver.resolve(matching_rules)?;
        Ok(decision)
    }
}
