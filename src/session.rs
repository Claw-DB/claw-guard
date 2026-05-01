use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::config::GuardConfig;
use crate::error::{GuardError, GuardResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClawSession {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub agent_id: Uuid,
    pub role: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PaginatedSessions {
    pub sessions: Vec<SessionInfo>,
    pub next_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionClaims {
    session_id: String,
    agent_id: String,
    role: String,
    scopes: Vec<String>,
    exp: usize,
}

#[derive(Clone)]
pub struct SessionManager {
    pool: SqlitePool,
    config: Arc<GuardConfig>,
}

impl SessionManager {
    pub fn new(pool: SqlitePool, config: Arc<GuardConfig>) -> Self {
        Self { pool, config }
    }

    pub async fn create_session(
        &self,
        agent_id: Uuid,
        role: &str,
        scopes: Vec<String>,
        ttl_secs: i64,
    ) -> GuardResult<ClawSession> {
        let session_id = Uuid::new_v4();
        let role_id = self.ensure_role(role, &scopes).await?;
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(ttl_secs);
        let claims = SessionClaims {
            session_id: session_id.to_string(),
            agent_id: agent_id.to_string(),
            role: role.to_owned(),
            scopes: scopes.clone(),
            exp: expires_at.timestamp() as usize,
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )?;

        sqlx::query(
            "INSERT INTO sessions (id, agent_id, role_id, scopes, created_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
        )
        .bind(session_id.to_string())
        .bind(agent_id.to_string())
        .bind(role_id.to_string())
        .bind(serde_json::to_string(&scopes)?)
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(ClawSession {
            session_id,
            agent_id,
            role: role.to_owned(),
            scopes,
            expires_at,
            token,
        })
    }

    pub async fn validate_session(&self, token: &str) -> GuardResult<ClawSession> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let token_data = decode::<SessionClaims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &validation,
        )?;
        let claims = token_data.claims;
        let session_id = Uuid::parse_str(&claims.session_id)?;
        let row = sqlx::query(
            "SELECT s.agent_id, s.scopes, s.expires_at, s.revoked, r.name AS role_name
             FROM sessions s
             JOIN roles r ON r.id = s.role_id
             WHERE s.id = ?1",
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(GuardError::SessionNotFound(session_id))?;

        let revoked: bool = row.try_get("revoked")?;
        if revoked {
            return Err(GuardError::SessionRevoked(session_id));
        }

        let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
        if expires_at < Utc::now() {
            return Err(GuardError::SessionExpired {
                session_id,
                expired_at: expires_at,
            });
        }

        let scopes: String = row.try_get("scopes")?;
        let scopes = serde_json::from_str(&scopes)?;
        let agent_id = Uuid::parse_str(&row.try_get::<String, _>("agent_id")?)?;
        let role: String = row.try_get("role_name")?;

        Ok(ClawSession {
            session_id,
            agent_id,
            role,
            scopes,
            expires_at,
            token: token.to_owned(),
        })
    }

    pub async fn revoke_session(&self, session_id: Uuid) -> GuardResult<()> {
        let result = sqlx::query("UPDATE sessions SET revoked = 1 WHERE id = ?1")
            .bind(session_id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(GuardError::SessionNotFound(session_id));
        }

        Ok(())
    }

    pub async fn list_active_sessions(
        &self,
        agent_id: Uuid,
        limit: u64,
        offset: u64,
    ) -> GuardResult<PaginatedSessions> {
        let rows = sqlx::query(
            "SELECT s.id, s.agent_id, s.scopes, s.created_at, s.expires_at, r.name AS role_name
             FROM sessions s
             JOIN roles r ON r.id = s.role_id
             WHERE s.agent_id = ?1 AND s.revoked = 0 AND s.expires_at > CURRENT_TIMESTAMP
             ORDER BY s.created_at DESC
             LIMIT ?2 OFFSET ?3",
        )
        .bind(agent_id.to_string())
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let sessions = rows
            .into_iter()
            .map(|row| {
                let session_id = Uuid::parse_str(&row.try_get::<String, _>("id")?)?;
                let scopes: String = row.try_get("scopes")?;
                Ok(SessionInfo {
                    session_id,
                    agent_id: Uuid::parse_str(&row.try_get::<String, _>("agent_id")?)?,
                    role: row.try_get("role_name")?,
                    scopes: serde_json::from_str(&scopes)?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                })
            })
            .collect::<GuardResult<Vec<_>>>()?;

        let next_offset = (!sessions.is_empty() && sessions.len() as u64 == limit).then_some(offset + limit);
        Ok(PaginatedSessions { sessions, next_offset })
    }

    async fn ensure_role(&self, role: &str, scopes: &[String]) -> GuardResult<Uuid> {
        if let Some(existing) = sqlx::query("SELECT id FROM roles WHERE name = ?1")
            .bind(role)
            .fetch_optional(&self.pool)
            .await?
        {
            let id: String = existing.try_get("id")?;
            return Ok(Uuid::parse_str(&id)?);
        }

        let role_id = Uuid::new_v4();
        sqlx::query("INSERT INTO roles (id, name, description, scopes) VALUES (?1, ?2, NULL, ?3)")
            .bind(role_id.to_string())
            .bind(role)
            .bind(serde_json::to_string(scopes)?)
            .execute(&self.pool)
            .await?;
        Ok(role_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sqlx::{sqlite::SqlitePoolOptions, Executor};

    use super::*;
    use crate::config::GuardConfig;

    async fn setup() -> (SessionManager, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory db should connect");
        pool.execute(
            "CREATE TABLE roles (id UUID PRIMARY KEY, name TEXT UNIQUE, description TEXT, scopes TEXT[]);
             CREATE TABLE sessions (id UUID PRIMARY KEY, agent_id UUID, role_id UUID, scopes TEXT[], created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, revoked BOOL);",
        )
        .await
        .expect("tables should be created");
        let config = Arc::new(GuardConfig {
            db_path: ":memory:".to_owned(),
            jwt_secret: crate::config::ZeroizeString::new("secret"),
            policy_dir: "policies".into(),
            tls_cert_path: "certs/server.crt".into(),
            tls_key_path: "certs/server.key".into(),
            risk_thresholds: crate::config::RiskThresholds::default(),
            sensitive_resources: Vec::new(),
            audit_flush_interval_ms: 100,
            audit_batch_size: 500,
        });
        (SessionManager::new(pool.clone(), config), pool)
    }

    #[tokio::test]
    async fn session_jwt_round_trip() {
        let (manager, _) = setup().await;
        let agent_id = Uuid::new_v4();
        let session = manager
            .create_session(agent_id, "analyst", vec!["tool:*".to_owned()], 60)
            .await
            .expect("session should be created");
        let validated = manager
            .validate_session(&session.token)
            .await
            .expect("session should validate");
        assert_eq!(validated.session_id, session.session_id);

        manager
            .revoke_session(session.session_id)
            .await
            .expect("session should be revoked");
        assert!(matches!(
            manager.validate_session(&session.token).await,
            Err(GuardError::SessionRevoked(_))
        ));
    }
}