#![allow(dead_code, unused_variables, unused_imports)]
use crate::context::EvaluationContext;
use crate::error::GuardResult;
use crate::policy::evaluator::PolicyEvaluator;
use crate::policy::model::AccessDecision;
use std::sync::Arc;

pub struct AccessChecker {
    evaluator: Arc<PolicyEvaluator>,
}

impl AccessChecker {
    pub fn new(evaluator: Arc<PolicyEvaluator>) -> Self {
        Self { evaluator }
    }

    pub async fn check(&self, ctx: &EvaluationContext) -> GuardResult<AccessDecision> {
        self.evaluator.evaluate(ctx).await
    }
}
