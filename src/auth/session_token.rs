#![allow(dead_code, unused_variables, unused_imports)]
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use uuid::Uuid;
use crate::context::session::SessionContext;
use crate::error::{GuardError, GuardResult};

pub struct SessionStore { sessions: DashMap<Uuid, SessionContext>, ttl_secs: u64 }

impl SessionStore {
    pub fn new(ttl_secs: u64) -> Self { Self { sessions: DashMap::new(), ttl_secs } }

    pub fn create(&self, agent_id: Uuid, workspace_id: Uuid, scopes: Vec<String>) -> SessionContext {
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let ctx = SessionContext {
            session_id,
            agent_id,
            workspace_id,
            scopes,
            created_at: now,
            expires_at: now + Duration::seconds(self.ttl_secs as i64),
            is_active: true,
        };
        self.sessions.insert(session_id, ctx.clone());
        ctx
    }

    pub fn get(&self, session_id: Uuid) -> GuardResult<SessionContext> {
        let ctx = self.sessions.get(&session_id).ok_or(GuardError::SessionNotFound(session_id))?.clone();
        if ctx.is_expired(Utc::now()) { return Err(GuardError::SessionExpired(session_id)); }
        Ok(ctx)
    }

    pub fn revoke(&self, session_id: Uuid) {
        self.sessions.remove(&session_id);
    }
}
