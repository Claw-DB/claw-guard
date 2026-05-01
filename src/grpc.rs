use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::audit::AuditFilter;
use crate::error::{GuardError, GuardResult};
use crate::guard::{AccessResult, Guard};
use crate::policy::PolicyRecord;
use crate::proto::guard::{
    guard_service_server::{GuardService, GuardServiceServer},
    AddPolicyRequest, AddPolicyResponse, AuditEntry as AuditEntryMsg, CheckAccessRequest,
    CheckAccessResponse, CreateSessionRequest, CreateSessionResponse, ListPoliciesRequest,
    ListPoliciesResponse, Policy, QueryAuditLogRequest, QueryAuditLogResponse,
    RemovePolicyRequest, RemovePolicyResponse, RevokeSessionRequest, RevokeSessionResponse,
    ValidateSessionRequest, ValidateSessionResponse,
};

#[derive(Clone)]
pub struct GrpcGuardService {
    guard: Arc<Guard>,
}

impl GrpcGuardService {
    pub fn new(guard: Arc<Guard>) -> Self {
        Self { guard }
    }

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
        let result = self
            .guard
            .check_access_with_task(&payload.session_token, &payload.action, &payload.resource, &payload.task)
            .await
            .map_err(Status::from)?;
        let response = match result {
            AccessResult::Allowed => CheckAccessResponse {
                decision: "allow".to_owned(),
                reason: String::new(),
                masked_fields: Vec::new(),
            },
            AccessResult::Denied { reason } => CheckAccessResponse {
                decision: "deny".to_owned(),
                reason,
                masked_fields: Vec::new(),
            },
            AccessResult::Masked { fields } => CheckAccessResponse {
                decision: "mask".to_owned(),
                reason: String::new(),
                masked_fields: fields.into_iter().map(|field| field.field_pattern).collect(),
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
            .session_manager
            .create_session(
                Uuid::parse_str(&payload.agent_id).map_err(|error| Status::invalid_argument(error.to_string()))?,
                &payload.role,
                payload.scopes,
                payload.ttl_secs,
            )
            .await
            .map_err(Status::from)?;
        Ok(Response::new(CreateSessionResponse {
            session_id: session.session_id.to_string(),
            agent_id: session.agent_id.to_string(),
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
        let token = request.into_inner().token;
        let response = match self.guard.session_manager.validate_session(&token).await {
            Ok(session) => ValidateSessionResponse {
                valid: true,
                session_id: session.session_id.to_string(),
                agent_id: session.agent_id.to_string(),
                role: session.role,
                scopes: session.scopes,
                expires_at: session.expires_at.timestamp(),
            },
            Err(_) => ValidateSessionResponse {
                valid: false,
                session_id: String::new(),
                agent_id: String::new(),
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
        let session_id = Uuid::parse_str(&request.into_inner().session_id)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        self.guard
            .session_manager
            .revoke_session(session_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(RevokeSessionResponse { revoked: true }))
    }

    async fn add_policy(
        &self,
        request: Request<AddPolicyRequest>,
    ) -> Result<Response<AddPolicyResponse>, Status> {
        let payload = request.into_inner();
        let policy = self
            .guard
            .policy_engine
            .add_policy_from_toml(&payload.policy_toml, &payload.name)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(AddPolicyResponse {
            policy: Some(policy_to_proto(policy)),
        }))
    }

    async fn list_policies(
        &self,
        _request: Request<ListPoliciesRequest>,
    ) -> Result<Response<ListPoliciesResponse>, Status> {
        let policies = self
            .guard
            .policy_engine
            .list_policies()
            .await
            .map_err(Status::from)?
            .into_iter()
            .map(policy_to_proto)
            .collect();
        Ok(Response::new(ListPoliciesResponse { policies }))
    }

    async fn remove_policy(
        &self,
        request: Request<RemovePolicyRequest>,
    ) -> Result<Response<RemovePolicyResponse>, Status> {
        let policy_id = Uuid::parse_str(&request.into_inner().policy_id)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        self.guard
            .policy_engine
            .remove_policy(policy_id)
            .await
            .map_err(Status::from)?;
        Ok(Response::new(RemovePolicyResponse { removed: true }))
    }

    async fn query_audit_log(
        &self,
        request: Request<QueryAuditLogRequest>,
    ) -> Result<Response<QueryAuditLogResponse>, Status> {
        let payload = request.into_inner();
        let filter = AuditFilter {
            session_id: parse_optional_uuid(&payload.session_id).map_err(Status::from)?,
            agent_id: parse_optional_uuid(&payload.agent_id).map_err(Status::from)?,
            decision: (!payload.decision.is_empty()).then_some(payload.decision),
            start_time: (payload.start_ts > 0).then_some(
                chrono::DateTime::from_timestamp(payload.start_ts, 0)
                    .ok_or_else(|| GuardError::Config("invalid start_ts".to_owned()))?,
            ),
            end_time: (payload.end_ts > 0).then_some(
                chrono::DateTime::from_timestamp(payload.end_ts, 0)
                    .ok_or_else(|| GuardError::Config("invalid end_ts".to_owned()))?,
            ),
            resource: (!payload.resource.is_empty()).then_some(payload.resource),
            limit: (payload.limit > 0).then_some(payload.limit),
        };
        let audit_entries = self
            .guard
            .query_audit(filter)
            .await
            .map_err(|error| Status::from(error))?;
        let entries: Vec<AuditEntryMsg> = audit_entries
            .into_iter()
            .map(|entry| AuditEntryMsg {
                id: entry.id.to_string(),
                session_id: entry
                    .session_id
                    .map(|value: uuid::Uuid| value.to_string())
                    .unwrap_or_default(),
                agent_id: entry.agent_id.to_string(),
                action: entry.action,
                resource: entry.resource,
                resource_id: entry.resource_id.unwrap_or_default(),
                decision: entry.decision,
                reason: entry.reason.unwrap_or_default(),
                risk_score: entry.risk_score,
                metadata_json: serde_json::to_string(&entry.metadata).unwrap_or_else(|_| "{}".to_owned()),
                ts: entry.ts.timestamp(),
            })
            .collect();
        Ok(Response::new(QueryAuditLogResponse { entries }))
    }
}

pub async fn serve(guard: Arc<Guard>, addr: SocketAddr) -> GuardResult<()> {
    let cert = tokio::fs::read(&guard.config().tls_cert_path).await?;
    let key = tokio::fs::read(&guard.config().tls_key_path).await?;
    let identity = Identity::from_pem(cert, key);
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))
        .map_err(|error| GuardError::Transport(error.to_string()))?
        .add_service(GrpcGuardService::new(guard).service())
        .serve(addr)
        .await
        .map_err(|error| GuardError::Transport(error.to_string()))
}

fn policy_to_proto(policy: PolicyRecord) -> Policy {
    Policy {
        id: policy.id.to_string(),
        name: policy.name,
        description: policy.description.unwrap_or_default(),
        priority: policy.priority,
        enabled: policy.enabled,
        rules_json: serde_json::to_string(&policy.rules).unwrap_or_else(|_| "[]".to_owned()),
    }
}

fn parse_optional_uuid(value: &str) -> GuardResult<Option<Uuid>> {
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Uuid::parse_str(value)?))
    }
}