use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::{GuardError, GuardResult};

/// Metadata for a stored API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// API key identifier.
    pub id: Uuid,
    /// Stored BLAKE3 hex digest of the raw key.
    pub key_hash: String,
    /// Workspace that owns the key.
    pub workspace_id: Uuid,
    /// Human-readable label for the key.
    pub label: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// Last successful use timestamp.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Creates, validates, revokes, and lists API keys.
#[derive(Clone)]
pub struct ApiKeyManager {
    pool: SqlitePool,
}

impl ApiKeyManager {
    /// Creates a new API key manager backed by a SQLite pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Generates, stores, and returns a new API key.
    pub async fn create_key(
        &self,
        workspace_id: Uuid,
        label: &str,
    ) -> GuardResult<(String, ApiKeyRecord)> {
        let mut bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw_key = URL_SAFE_NO_PAD.encode(bytes);
        let key_hash = blake3::hash(raw_key.as_bytes()).to_hex().to_string();
        let id = Uuid::new_v4();
        let created_at = Utc::now();

        sqlx::query(
            "INSERT INTO api_keys (id, key_hash, workspace_id, label, created_at, revoked, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL)",
        )
        .bind(id.to_string())
        .bind(&key_hash)
        .bind(workspace_id.to_string())
        .bind(if label.is_empty() { None::<String> } else { Some(label.to_owned()) })
        .bind(created_at.timestamp_millis())
        .execute(&self.pool)
        .await?;

        Ok((
            raw_key,
            ApiKeyRecord {
                id,
                key_hash,
                workspace_id,
                label: (!label.is_empty()).then(|| label.to_owned()),
                created_at,
                revoked: false,
                last_used_at: None,
            },
        ))
    }

    /// Validates a raw API key against the stored hash.
    pub async fn validate_key(&self, raw_key: &str) -> GuardResult<ApiKeyRecord> {
        let candidate_hash = blake3::hash(raw_key.as_bytes());
        let candidate_hex = candidate_hash.to_hex().to_string();
        let row = sqlx::query(
            "SELECT id, key_hash, workspace_id, label, created_at, revoked, last_used_at
             FROM api_keys WHERE key_hash = ?1 LIMIT 1",
        )
        .bind(&candidate_hex)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(GuardError::InvalidToken)?;

        if row.try_get::<i64, _>("revoked")? != 0 {
            return Err(GuardError::InvalidToken);
        }

        let stored_hex: String = row.try_get("key_hash")?;
        let stored_hash = blake3::Hash::from_hex(stored_hex.as_str()).map_err(|error| {
            GuardError::ConfigError(format!("invalid stored key hash: {error}"))
        })?;
        if stored_hash != candidate_hash {
            return Err(GuardError::InvalidToken);
        }

        let record = row_to_api_key_record(&row)?;
        let pool = self.pool.clone();
        let id = record.id;
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2")
                .bind(Utc::now().timestamp_millis())
                .bind(id.to_string())
                .execute(&pool)
                .await;
        });

        Ok(record)
    }

    /// Revokes an API key.
    pub async fn revoke_key(&self, id: Uuid) -> GuardResult<()> {
        sqlx::query("UPDATE api_keys SET revoked = 1 WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Lists API keys for a workspace.
    pub async fn list_keys(&self, workspace_id: Uuid) -> GuardResult<Vec<ApiKeyRecord>> {
        let rows = sqlx::query(
            "SELECT id, key_hash, workspace_id, label, created_at, revoked, last_used_at
             FROM api_keys WHERE workspace_id = ?1 ORDER BY created_at DESC",
        )
        .bind(workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_api_key_record).collect()
    }
}

fn row_to_api_key_record(row: &sqlx::sqlite::SqliteRow) -> GuardResult<ApiKeyRecord> {
    Ok(ApiKeyRecord {
        id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
        key_hash: row.try_get("key_hash")?,
        workspace_id: Uuid::parse_str(&row.try_get::<String, _>("workspace_id")?)?,
        label: row.try_get("label")?,
        created_at: from_ms(row.try_get("created_at")?)?,
        revoked: row.try_get::<i64, _>("revoked")? != 0,
        last_used_at: row
            .try_get::<Option<i64>, _>("last_used_at")?
            .map(from_ms)
            .transpose()?,
    })
}

fn from_ms(value: i64) -> GuardResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(value)
        .ok_or_else(|| GuardError::ConfigError(format!("invalid timestamp millis: {value}")))
}
