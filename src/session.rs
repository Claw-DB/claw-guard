use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::config::GuardConfig;
use crate::error::{GuardError, GuardResult};
use crate::types::GuardSession;

/// Pagination options for list APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListOptions {
    /// Maximum number of items to return.
    pub limit: u64,
    /// Number of items to skip.
    pub offset: u64,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}

/// Page of list results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage<T> {
    /// Returned items.
    pub items: Vec<T>,
    /// Offset for the next page if more results exist.
    pub next_offset: Option<u64>,
}

/// Session row returned by list operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Session identifier.
    pub id: Uuid,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Role associated with the session.
    pub role: String,
    /// Session scopes.
    pub scopes: Vec<String>,
    /// Session creation time.
    pub created_at: DateTime<Utc>,
    /// Session expiration time.
    pub expires_at: DateTime<Utc>,
    /// Revocation flag.
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionClaims {
    sub: String,
    agent_id: String,
    workspace_id: String,
    role: String,
    scopes: Vec<String>,
    exp: usize,
}

/// Issues, validates, revokes, and lists guard sessions.
#[derive(Clone)]
pub struct SessionManager {
    pool: SqlitePool,
    config: Arc<GuardConfig>,
}

impl SessionManager {
    /// Creates a session manager backed by the provided database pool.
    pub fn new(pool: SqlitePool, config: Arc<GuardConfig>) -> Self {
        Self { pool, config }
    }

    /// Creates a new JWT-backed session and stores it in SQLite.
    pub async fn create_session(
        &self,
        agent_id: Uuid,
        workspace_id: Uuid,
        role: &str,
        scopes: Vec<String>,
        ttl_secs: u64,
    ) -> GuardResult<GuardSession> {
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(ttl_secs as i64);
        let claims = SessionClaims {
            sub: id.to_string(),
            agent_id: agent_id.to_string(),
            workspace_id: workspace_id.to_string(),
            role: role.to_owned(),
            scopes: scopes.clone(),
            exp: expires_at.timestamp() as usize,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.expose_secret().as_bytes()),
        )?;

        sqlx::query(
            "INSERT INTO sessions (id, agent_id, workspace_id, role, scopes, created_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        )
        .bind(id.to_string())
        .bind(agent_id.to_string())
        .bind(workspace_id.to_string())
        .bind(role)
        .bind(serde_json::to_string(&scopes)?)
        .bind(created_at.timestamp_millis())
        .bind(expires_at.timestamp_millis())
        .execute(&self.pool)
        .await?;

        Ok(GuardSession {
            id,
            agent_id,
            workspace_id,
            role: role.to_owned(),
            scopes,
            expires_at,
            token,
        })
    }

    /// Validates a session JWT and confirms the backing row remains active.
    pub async fn validate_session(&self, token: &str) -> GuardResult<GuardSession> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let token_data = decode::<SessionClaims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.expose_secret().as_bytes()),
            &validation,
        )
        .map_err(|_| GuardError::InvalidToken)?;

        let claims = token_data.claims;
        let session_id = Uuid::parse_str(&claims.sub)?;
        let row = sqlx::query(
            "SELECT id, agent_id, workspace_id, role, scopes, created_at, expires_at, revoked
             FROM sessions WHERE id = ?1",
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(GuardError::InvalidToken)?;

        let record = row_to_session_record(&row)?;
        if record.revoked {
            return Err(GuardError::SessionRevoked);
        }
        if record.expires_at <= Utc::now() {
            return Err(GuardError::SessionExpired);
        }

        Ok(GuardSession {
            id: record.id,
            agent_id: record.agent_id,
            workspace_id: record.workspace_id,
            role: record.role,
            scopes: record.scopes,
            expires_at: record.expires_at,
            token: token.to_owned(),
        })
    }

    /// Revokes a session row.
    pub async fn revoke_session(&self, session_id: Uuid) -> GuardResult<()> {
        sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ?1")
            .bind(session_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Lists active sessions for an agent.
    pub async fn list_active_sessions(
        &self,
        agent_id: Uuid,
        opts: Option<ListOptions>,
    ) -> GuardResult<ListPage<SessionRecord>> {
        let opts = opts.unwrap_or_default();
        let rows = sqlx::query(
            "SELECT id, agent_id, workspace_id, role, scopes, created_at, expires_at, revoked
             FROM sessions
             WHERE agent_id = ?1 AND revoked = 0 AND expires_at > ?2
             ORDER BY created_at DESC
             LIMIT ?3 OFFSET ?4",
        )
        .bind(agent_id.to_string())
        .bind(Utc::now().timestamp_millis())
        .bind(opts.limit as i64)
        .bind(opts.offset as i64)
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .iter()
            .map(row_to_session_record)
            .collect::<GuardResult<Vec<_>>>()?;
        let next_offset = (items.len() as u64 == opts.limit).then_some(opts.offset + opts.limit);

        Ok(ListPage { items, next_offset })
    }

    /// Confirms that a session row is still active.
    pub async fn assert_session_active(&self, session: &GuardSession) -> GuardResult<()> {
        let row = sqlx::query("SELECT revoked, expires_at FROM sessions WHERE id = ?1")
            .bind(session.id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(GuardError::InvalidToken)?;
        let revoked = row.try_get::<i64, _>("revoked")? != 0;
        if revoked {
            return Err(GuardError::SessionRevoked);
        }
        let expires_at = from_ms(row.try_get("expires_at")?)?;
        if expires_at <= Utc::now() {
            return Err(GuardError::SessionExpired);
        }
        Ok(())
    }
}

fn row_to_session_record(row: &sqlx::sqlite::SqliteRow) -> GuardResult<SessionRecord> {
    Ok(SessionRecord {
        id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
        agent_id: Uuid::parse_str(&row.try_get::<String, _>("agent_id")?)?,
        workspace_id: Uuid::parse_str(&row.try_get::<String, _>("workspace_id")?)?,
        role: row.try_get("role")?,
        scopes: serde_json::from_str(&row.try_get::<String, _>("scopes")?)?,
        created_at: from_ms(row.try_get("created_at")?)?,
        expires_at: from_ms(row.try_get("expires_at")?)?,
        revoked: row.try_get::<i64, _>("revoked")? != 0,
    })
}

fn from_ms(value: i64) -> GuardResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(value)
        .ok_or_else(|| GuardError::ConfigError(format!("invalid timestamp millis: {value}")))
}
