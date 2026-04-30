#![allow(dead_code, unused_variables, unused_imports)]
pub mod environment;
pub mod intent;
pub mod request;
pub mod session;

pub use environment::EnvironmentContext;
pub use intent::IntentContext;
pub use request::AccessRequest;
pub use session::SessionContext;

#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub request: AccessRequest,
    pub session: Option<SessionContext>,
    pub intent: IntentContext,
    pub environment: EnvironmentContext,
    pub risk_score: f64,
}
