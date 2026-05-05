//! Security, session, policy, masking, and audit primitives for ClawDB.

/// Batched audit logging and querying.
pub mod audit;
/// Runtime configuration loading.
pub mod config;
/// Error types returned by the guard engine.
pub mod error;
/// gRPC service integration.
pub mod grpc;
/// Main public guard API.
pub mod guard;
/// API key management.
pub mod keys;
/// Data masking engine.
pub mod masking;
/// Policy engine and rule types.
pub mod policy;
/// Generated protobuf modules.
pub mod proto;
/// Session management.
pub mod session;
/// Shared public data types.
pub mod types;

pub use audit::{AuditEntry, AuditFilter, AuditReader, AuditWriter};
pub use config::GuardConfig;
pub use error::{GuardError, GuardResult};
pub use guard::Guard;
pub use keys::{ApiKeyManager, ApiKeyRecord};
pub use masking::{MaskDirective, MaskType, MaskingEngine};
pub use policy::{Condition, EvalContext, Policy, PolicyEngine, PolicyRule};
pub use session::{ListOptions, ListPage, SessionManager, SessionRecord};
pub use types::{AccessResult, GuardSession, PolicyDecision};
