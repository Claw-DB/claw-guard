use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::audit::AuditFilter;
use crate::error::{GuardError, GuardResult};
use crate::guard::Guard;
use crate::proto::guard::{
    guard_service_server::{GuardService, GuardServiceServer},
    AddPolicyRequest, AddPolicyResponse, AuditEntry as AuditEntryMessage, CheckAccessRequest,
    CheckAccessResponse, CreateSessionRequest, CreateSessionResponse, ListPoliciesRequest,
    ListPoliciesResponse, Policy as PolicyMessage, QueryAuditLogRequest, QueryAuditLogResponse,
    RemovePolicyRequest, RemovePolicyResponse, RevokeSessionRequest, RevokeSessionResponse,
    ValidateSessionRequest, ValidateSessionResponse,
};
use crate::types::PolicyDecision;

/// gRPC wrapper over the guard engine.
#[derive(Clone)]
pub struct GrpcGuardService {
    guard: Arc<Guard>,
}

impl GrpcGuardService {
    /// Creates a new gRPC service.
    pub fn new(guard: Arc<Guard>) -> Self {
        Self { guard }
    }

    /// Returns the tonic service implementation.
    pub fn service(self) -> GuardServiceServer<Self> {
        GuardServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl GuardService for GrpcGuardService {
    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
    ) -> Result<Response<CheckAccessResponse>, Status> {
        let payload = request.into_inner();
        let session = self
            .guard
            .sessions()
            .validate_session(&payload.session_token)
            .await?;
        let decision = self
            .guard
            .check_access_with_task(&session, &payload.action, &payload.resource, &payload.task)
            .await?;

        let response = match decision {
            PolicyDecision::Allow => CheckAccessResponse {
                decision: "allow".to_owned(),
                reason: String::new(),
                masked_fields: Vec::new(),
            },
            PolicyDecision::Deny { reason } => CheckAccessResponse {
                decision: "deny".to_owned(),
                reason,
                masked_fields: Vec::new(),
            },
            PolicyDecision::Mask { fields } => CheckAccessResponse {
                decision: "mask".to_owned(),
                reason: String::new(),
                masked_fields: fields,
            },
        };
        Ok(Response::new(response))
    }

    async fn create_session(
        &self,
        request: Request<CreateSessionRequest>,
    ) -> Result<Response<CreateSessionResponse>, Status> {
        let payload = request.into_inner();
        let session = self
            .guard
            .sessions()
            .create_session(
                Uuid::parse_str(&payload.agent_id).map_err(invalid_argument)?,
                Uuid::parse_str(&payload.workspace_id).map_err(invalid_argument)?,
                &payload.role,
                payload.scopes,
                payload.ttl_secs as u64,
            )
            .await?;

        Ok(Response::new(CreateSessionResponse {
            session_id: session.id.to_string(),
            agent_id: session.agent_id.to_string(),
            workspace_id: session.workspace_id.to_string(),
            role: session.role,
            scopes: session.scopes,
            token: session.token,
            expires_at: session.expires_at.timestamp(),
        }))
    }

    async fn validate_session(
        &self,
        request: Request<ValidateSessionRequest>,
    ) -> Result<Response<ValidateSessionResponse>, Status> {
        let session = self
            .guard
            .sessions()
            .validate_session(&request.into_inner().token)
            .await;
        let response = match session {
            Ok(session) => ValidateSessionResponse {
                valid: true,
                session_id: session.id.to_string(),
                agent_id: session.agent_id.to_string(),
                workspace_id: session.workspace_id.to_string(),
                role: session.role,
                scopes: session.scopes,
                expires_at: session.expires_at.timestamp(),
            },
            Err(_) => ValidateSessionResponse {
                valid: false,
                session_id: String::new(),
                agent_id: String::new(),
                workspace_id: String::new(),
                role: String::new(),
                scopes: Vec::new(),
                expires_at: 0,
            },
        };
        Ok(Response::new(response))
    }

    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<RevokeSessionResponse>, Status> {
        let session_id =
            Uuid::parse_str(&request.into_inner().session_id).map_err(invalid_argument)?;
        self.guard.sessions().revoke_session(session_id).await?;
        Ok(Response::new(RevokeSessionResponse { revoked: true }))
    }

    async fn add_policy(
        &self,
        request: Request<AddPolicyRequest>,
    ) -> Result<Response<AddPolicyResponse>, Status> {
        let payload = request.into_inner();
        let policy = self
            .guard
            .policy_engine()
            .add_policy_from_toml(&payload.policy_toml, &payload.name)
            .await?;
        Ok(Response::new(AddPolicyResponse {
            policy: Some(policy_to_proto(policy)?),
        }))
    }

    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let policies = self
            .guard
            .policy_engine()
            .list_policies()
            .await?
            .into_iter()
            .map(policy_to_proto)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListPoliciesResponse { policies }))
    }

    async fn remove_policy(
        &self,
        request: Request<RemovePolicyRequest>,
    ) -> Result<Response<RemovePolicyResponse>, Status> {
        let policy_id =
            Uuid::parse_str(&request.into_inner().policy_id).map_err(invalid_argument)?;
        self.guard.policy_engine().remove_policy(policy_id).await?;
        Ok(Response::new(RemovePolicyResponse { removed: true }))
    }

    async fn query_audit_log(
        &self,
        request: Request<QueryAuditLogRequest>,
    ) -> Result<Response<QueryAuditLogResponse>, Status> {
        let payload = request.into_inner();
        let entries = self
            .guard
            .query_audit(AuditFilter {
                workspace_id: parse_optional_uuid(&payload.workspace_id)?,
                session_id: parse_optional_uuid(&payload.session_id)?,
                decision: (!payload.decision.is_empty()).then_some(payload.decision),
                start_time: (payload.start_ts > 0).then_some(from_secs(payload.start_ts)?),
                end_time: (payload.end_ts > 0).then_some(from_secs(payload.end_ts)?),
                resource: (!payload.resource.is_empty()).then_some(payload.resource),
                limit: (payload.limit > 0).then_some(payload.limit),
            })
            .await?;

        Ok(Response::new(QueryAuditLogResponse {
            entries: entries
                .into_iter()
                .map(|entry| AuditEntryMessage {
                    id: entry.id.to_string(),
                    session_id: entry
                        .session_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    workspace_id: entry.workspace_id.to_string(),
                    agent_id: entry
                        .agent_id
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    action: entry.action,
                    resource: entry.resource,
                    resource_id: entry.resource_id.unwrap_or_default(),
                    decision: entry.decision,
                    reason: entry.reason.unwrap_or_default(),
                    risk_score: entry.risk_score,
                    metadata_json: serde_json::to_string(&entry.metadata)
                        .unwrap_or_else(|_| "{}".to_owned()),
                    ts: entry.ts.timestamp(),
                })
                .collect(),
        }))
    }
}

/// Starts the gRPC server.
pub async fn serve(guard: Arc<Guard>, addr: SocketAddr) -> GuardResult<()> {
    Server::builder()
        .add_service(GrpcGuardService::new(guard).service())
        .serve(addr)
        .await
        .map_err(|error| GuardError::ConfigError(format!("gRPC server failed: {error}")))
}

fn parse_optional_uuid(value: &str) -> Result<Option<Uuid>, Status> {
    if value.is_empty() {
        Ok(None)
    } else {
        Uuid::parse_str(value).map(Some).map_err(invalid_argument)
    }
}

fn invalid_argument(error: impl std::fmt::Display) -> Status {
    Status::invalid_argument(error.to_string())
}

fn from_secs(value: i64) -> Result<chrono::DateTime<chrono::Utc>, Status> {
    chrono::DateTime::from_timestamp(value, 0)
        .ok_or_else(|| Status::invalid_argument("invalid timestamp"))
}

fn policy_to_proto(policy: crate::policy::Policy) -> Result<PolicyMessage, Status> {
    Ok(PolicyMessage {
        id: policy.id.to_string(),
        name: policy.name,
        description: policy.description.unwrap_or_default(),
        priority: policy.priority,
        enabled: policy.enabled,
        rules_json: serde_json::to_string(&policy.rules).map_err(|error| {
            Status::internal(format!("failed to serialize policy rules: {error}"))
        })?,
    })
}
