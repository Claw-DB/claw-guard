#![allow(dead_code, unused_variables, unused_imports)]
use std::sync::Arc;
use crate::config::GuardConfig;
use crate::policy::evaluator::PolicyEvaluator;
use crate::policy::resolver::ConflictResolver;
use crate::policy::store::PolicyStore;
use crate::access::checker::AccessChecker;
use crate::error::GuardResult;

pub struct GuardEngine {
    pub config: Arc<GuardConfig>,
    pub checker: Arc<AccessChecker>,
}

impl GuardEngine {
    pub async fn from_config(config: GuardConfig) -> GuardResult<Self> {
        let config = Arc::new(config);
        let store = Arc::new(PolicyStore::new(&config.database_url, config.clone()).await?);
        let resolver = ConflictResolver::new(config.clone());
        let evaluator = Arc::new(PolicyEvaluator::new(store, resolver));
        let checker = Arc::new(AccessChecker::new(evaluator));
        Ok(Self { config, checker })
    }
}
