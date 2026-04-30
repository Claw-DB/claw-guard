#![allow(dead_code, unused_variables, unused_imports)]
use crate::config::GuardConfig;
use crate::error::{GuardError, GuardResult};
use crate::policy::compiler::GplCompiler;
use crate::policy::model::Policy;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use tokio_stream::Stream;
use uuid::Uuid;

pub struct PolicyStore {
    pool: PgPool,
    cache: DashMap<Uuid, Arc<Vec<Policy>>>,
    pub config: Arc<GuardConfig>,
}

impl PolicyStore {
    pub async fn new(database_url: &str, config: Arc<GuardConfig>) -> GuardResult<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self {
            pool,
            cache: DashMap::new(),
            config,
        })
    }

    pub async fn get_active(&self, workspace_id: Uuid) -> GuardResult<Vec<Policy>> {
        if let Some(cached) = self.cache.get(&workspace_id) {
            return Ok((**cached).clone());
        }
        self.load_from_db(workspace_id).await
    }

    async fn load_from_db(&self, workspace_id: Uuid) -> GuardResult<Vec<Policy>> {
        let rows = sqlx::query(
            "SELECT source_text, compiled_json FROM policies WHERE workspace_id = $1 AND is_active = TRUE"
        )
        .bind(workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut policies = Vec::new();
        for row in &rows {
            let source: String = row.try_get("source_text").map_err(GuardError::Database)?;
            let policy = GplCompiler::compile(&source, workspace_id)?;
            policies.push(policy);
        }

        let arc = Arc::new(policies.clone());
        self.cache.insert(workspace_id, arc);
        Ok(policies)
    }

    pub async fn upsert(&self, workspace_id: Uuid, source: &str) -> GuardResult<Policy> {
        let policy = GplCompiler::compile(source, workspace_id)?;
        let hash_hex = hex::encode(policy.source_hash);
        let compiled = serde_json::to_string(&policy)?;

        sqlx::query(
            "INSERT INTO policies (id, workspace_id, name, version, source_text, compiled_json, source_hash, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
             ON CONFLICT (id) DO UPDATE SET source_text = EXCLUDED.source_text, compiled_json = EXCLUDED.compiled_json, updated_at = NOW()"
        )
        .bind(policy.id.to_string())
        .bind(workspace_id.to_string())
        .bind(&policy.name)
        .bind(policy.version as i32)
        .bind(source)
        .bind(&compiled)
        .bind(&hash_hex)
        .execute(&self.pool)
        .await?;

        self.cache.remove(&workspace_id);
        Ok(policy)
    }

    pub async fn reload(&self, workspace_id: Uuid) -> GuardResult<usize> {
        self.cache.remove(&workspace_id);
        let policies = self.load_from_db(workspace_id).await?;
        Ok(policies.len())
    }

    pub fn watch_changes(&self) -> impl Stream<Item = Uuid> {
        async_stream::stream! {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                yield Uuid::nil();
            }
        }
    }
}
