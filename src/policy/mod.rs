use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Local, Timelike, Utc};
use glob::glob;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::GuardConfig;
use crate::error::{GuardError, GuardResult};
use crate::masking::MaskType;
use crate::types::PolicyDecision;

/// A policy rule evaluated in order within a policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyRule {
    /// Allows the request if the condition matches.
    AllowIf { condition: Condition },
    /// Denies the request if the condition matches.
    DenyIf {
        condition: Condition,
        reason: String,
    },
    /// Masks a matching field using the configured mask type.
    MaskField {
        field_pattern: String,
        mask_type: MaskType,
    },
}

/// Condition expression supported by the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Condition {
    /// Matches an exact task name.
    TaskMatches(String),
    /// Matches an exact role name.
    RoleIs(String),
    /// Matches when a scope is present.
    ScopeContains(String),
    /// Matches when the risk score is above the threshold.
    RiskAbove(f64),
    /// Matches an exact resource name.
    ResourceIs(String),
    /// Matches an exact workspace id.
    WorkspaceIs(Uuid),
    /// Logical AND.
    And(Box<Condition>, Box<Condition>),
    /// Logical OR.
    Or(Box<Condition>, Box<Condition>),
    /// Logical NOT.
    Not(Box<Condition>),
}

/// Context used for policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalContext {
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Workspace identifier.
    pub workspace_id: Uuid,
    /// Role name.
    pub role: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Task name.
    pub task: String,
    /// Resource name.
    pub resource: String,
    /// Action name.
    pub action: String,
    /// Risk score in the range `[0.0, 1.0]`.
    pub risk_score: f64,
}

/// Persisted policy definition.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// Policy identifier.
    pub id: Uuid,
    /// Unique policy name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Ordered rules.
    pub rules: Vec<PolicyRule>,
    /// Higher values are evaluated first.
    pub priority: i32,
    /// Whether the policy is enabled.
    pub enabled: bool,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct PolicyFileRoot {
    #[serde(default)]
    policies: Vec<PolicyFile>,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    name: Option<String>,
    description: Option<String>,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    rules: Vec<PolicyRuleFile>,
}

#[derive(Debug, Deserialize)]
struct PolicyRuleFile {
    #[serde(rename = "type")]
    kind: String,
    reason: Option<String>,
    condition: Option<toml::Value>,
    field_pattern: Option<String>,
    mask_type: Option<toml::Value>,
}

/// Policy engine with a read-through cache backed by SQLite.
#[derive(Clone)]
pub struct PolicyEngine {
    pool: SqlitePool,
    config: Arc<GuardConfig>,
    cache: Arc<RwLock<Vec<Policy>>>,
}

impl PolicyEngine {
    /// Creates a new policy engine.
    pub fn new(pool: SqlitePool, config: Arc<GuardConfig>) -> Self {
        Self {
            pool,
            config,
            cache: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Evaluates enabled policies in descending priority order.
    pub async fn evaluate(&self, ctx: &EvalContext) -> GuardResult<PolicyDecision> {
        let policies = self.cached_policies().await?;
        for policy in policies {
            for rule in &policy.rules {
                match rule {
                    PolicyRule::AllowIf { condition } if condition.matches(ctx) => {
                        return Ok(PolicyDecision::Allow);
                    }
                    PolicyRule::DenyIf { condition, reason } if condition.matches(ctx) => {
                        return Ok(PolicyDecision::Deny {
                            reason: reason.clone(),
                        });
                    }
                    PolicyRule::MaskField { field_pattern, .. } => {
                        return Ok(PolicyDecision::Mask {
                            fields: vec![field_pattern.clone()],
                        });
                    }
                    _ => {}
                }
            }
        }

        Ok(PolicyDecision::Deny {
            reason: "no matching policy rule".to_owned(),
        })
    }

    /// Computes a risk score for the provided context.
    pub fn compute_risk(&self, ctx: &EvalContext) -> f64 {
        let mut score: f64 = 0.0;
        let action = ctx.action.to_ascii_lowercase();
        if action.contains("write") || action.contains("update") {
            score += 0.3;
        }
        if action.contains("delete") {
            score += 0.5;
        }
        if self
            .config
            .sensitive_resources
            .iter()
            .any(|resource| resource == &ctx.resource)
        {
            score += 0.3;
        }
        let hour = Local::now().hour() as u8;
        if hour < self.config.business_hours_start_hour
            || hour >= self.config.business_hours_end_hour
        {
            score += 0.1;
        }
        score.clamp(0.0, 1.0)
    }

    /// Loads all TOML policy files from a directory and upserts them into SQLite.
    pub async fn load_from_dir(&self, dir: &Path) -> GuardResult<usize> {
        if !dir.exists() {
            return Ok(0);
        }

        let pattern = dir.join("*.toml").to_string_lossy().to_string();
        let mut loaded = 0_usize;
        for entry in glob(&pattern).map_err(|error| GuardError::ConfigError(error.to_string()))? {
            let path = entry.map_err(|error| GuardError::ConfigError(error.to_string()))?;
            let source = std::fs::read_to_string(&path)?;
            self.add_policy_from_toml(
                &source,
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("policy"),
            )
            .await?;
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Parses one TOML source string and upserts the contained policies.
    pub async fn add_policy_from_toml(
        &self,
        source: &str,
        fallback_name: &str,
    ) -> GuardResult<Policy> {
        let policies = parse_policy_source(source, fallback_name)?;
        let mut last = None;
        for policy in policies {
            self.upsert_policy(&policy).await?;
            last = Some(policy);
        }
        last.ok_or_else(|| GuardError::ConfigError("policy file contained no policies".to_owned()))
    }

    /// Lists persisted policies in evaluation order.
    pub async fn list_policies(&self) -> GuardResult<Vec<Policy>> {
        self.load_policies_from_db().await
    }

    /// Removes a policy by id.
    pub async fn remove_policy(&self, policy_id: Uuid) -> GuardResult<()> {
        sqlx::query("DELETE FROM policies WHERE id = ?1")
            .bind(policy_id.to_string())
            .execute(&self.pool)
            .await?;
        self.invalidate_cache().await;
        Ok(())
    }

    async fn upsert_policy(&self, policy: &Policy) -> GuardResult<()> {
        sqlx::query(
            "INSERT INTO policies (id, name, description, rules, priority, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                rules = excluded.rules,
                priority = excluded.priority,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at",
        )
        .bind(policy.id.to_string())
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(serde_json::to_string(&policy.rules)?)
        .bind(policy.priority)
        .bind(if policy.enabled { 1_i64 } else { 0_i64 })
        .bind(policy.created_at.timestamp_millis())
        .bind(policy.updated_at.timestamp_millis())
        .execute(&self.pool)
        .await?;
        self.invalidate_cache().await;
        Ok(())
    }

    async fn cached_policies(&self) -> GuardResult<Vec<Policy>> {
        {
            let cache = self.cache.read().await;
            if !cache.is_empty() {
                return Ok(cache.clone());
            }
        }

        let policies = self.load_policies_from_db().await?;
        let mut cache = self.cache.write().await;
        *cache = policies.clone();
        Ok(policies)
    }

    async fn load_policies_from_db(&self) -> GuardResult<Vec<Policy>> {
        let rows = sqlx::query(
            "SELECT id, name, description, rules, priority, enabled, created_at, updated_at
             FROM policies WHERE enabled = 1 ORDER BY priority DESC, updated_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(row_to_policy).collect()
    }

    async fn invalidate_cache(&self) {
        self.cache.write().await.clear();
    }
}

impl Condition {
    fn matches(&self, ctx: &EvalContext) -> bool {
        match self {
            Self::TaskMatches(value) => ctx.task == *value,
            Self::RoleIs(value) => ctx.role == *value,
            Self::ScopeContains(value) => ctx.scopes.iter().any(|scope| scope == value),
            Self::RiskAbove(value) => ctx.risk_score > *value,
            Self::ResourceIs(value) => ctx.resource == *value,
            Self::WorkspaceIs(value) => ctx.workspace_id == *value,
            Self::And(left, right) => left.matches(ctx) && right.matches(ctx),
            Self::Or(left, right) => left.matches(ctx) || right.matches(ctx),
            Self::Not(inner) => !inner.matches(ctx),
        }
    }
}

fn parse_policy_source(source: &str, fallback_name: &str) -> GuardResult<Vec<Policy>> {
    if source.contains("[[policies]]") {
        let root: PolicyFileRoot = toml::from_str(source)?;
        root.policies
            .into_iter()
            .enumerate()
            .map(|(index, policy)| policy_from_file(policy, &format!("{fallback_name}-{index}")))
            .collect()
    } else {
        let policy: PolicyFile = toml::from_str(source)?;
        Ok(vec![policy_from_file(policy, fallback_name)?])
    }
}

fn policy_from_file(policy: PolicyFile, fallback_name: &str) -> GuardResult<Policy> {
    let now = Utc::now();
    Ok(Policy {
        id: Uuid::new_v4(),
        name: policy.name.unwrap_or_else(|| fallback_name.to_owned()),
        description: policy.description,
        rules: policy
            .rules
            .into_iter()
            .map(parse_rule)
            .collect::<GuardResult<Vec<_>>>()?,
        priority: policy.priority,
        enabled: policy.enabled,
        created_at: now,
        updated_at: now,
    })
}

fn parse_rule(rule: PolicyRuleFile) -> GuardResult<PolicyRule> {
    match rule.kind.as_str() {
        "allow_if" => Ok(PolicyRule::AllowIf {
            condition: parse_condition(rule.condition.as_ref().ok_or_else(|| {
                GuardError::ConfigError("allow_if requires condition".to_owned())
            })?)?,
        }),
        "deny_if" => Ok(PolicyRule::DenyIf {
            condition: parse_condition(rule.condition.as_ref().ok_or_else(|| {
                GuardError::ConfigError("deny_if requires condition".to_owned())
            })?)?,
            reason: rule
                .reason
                .ok_or_else(|| GuardError::ConfigError("deny_if requires reason".to_owned()))?,
        }),
        "mask_field" => Ok(PolicyRule::MaskField {
            field_pattern: rule.field_pattern.ok_or_else(|| {
                GuardError::ConfigError("mask_field requires field_pattern".to_owned())
            })?,
            mask_type: parse_mask_type(rule.mask_type.as_ref().ok_or_else(|| {
                GuardError::ConfigError("mask_field requires mask_type".to_owned())
            })?)?,
        }),
        _ => Err(GuardError::ConfigError(format!(
            "unsupported rule type: {}",
            rule.kind
        ))),
    }
}

fn parse_condition(value: &toml::Value) -> GuardResult<Condition> {
    let table = value
        .as_table()
        .ok_or_else(|| GuardError::ConfigError("condition must be a table".to_owned()))?;

    if let Some(items) = table.get("and") {
        return fold_conditions(items, Condition::And);
    }
    if let Some(items) = table.get("or") {
        return fold_conditions(items, Condition::Or);
    }
    if let Some(item) = table.get("not") {
        return Ok(Condition::Not(Box::new(parse_condition(item)?)));
    }
    if let Some(value) = table.get("task_matches").and_then(toml::Value::as_str) {
        return Ok(Condition::TaskMatches(value.to_owned()));
    }
    if let Some(value) = table.get("role_is").and_then(toml::Value::as_str) {
        return Ok(Condition::RoleIs(value.to_owned()));
    }
    if let Some(value) = table.get("scope_contains").and_then(toml::Value::as_str) {
        return Ok(Condition::ScopeContains(value.to_owned()));
    }
    if let Some(value) = table.get("risk_above").and_then(toml::Value::as_float) {
        return Ok(Condition::RiskAbove(value));
    }
    if let Some(value) = table.get("resource_is").and_then(toml::Value::as_str) {
        return Ok(Condition::ResourceIs(value.to_owned()));
    }
    if let Some(value) = table.get("workspace_is").and_then(toml::Value::as_str) {
        return Ok(Condition::WorkspaceIs(Uuid::parse_str(value)?));
    }

    Err(GuardError::ConfigError(
        "unsupported condition shape".to_owned(),
    ))
}

fn fold_conditions(
    value: &toml::Value,
    combine: fn(Box<Condition>, Box<Condition>) -> Condition,
) -> GuardResult<Condition> {
    let items = value
        .as_array()
        .ok_or_else(|| GuardError::ConfigError("logical conditions must be arrays".to_owned()))?;
    let mut iter = items.iter().map(parse_condition);
    let first = iter.next().transpose()?.ok_or_else(|| {
        GuardError::ConfigError("logical conditions must not be empty".to_owned())
    })?;

    iter.try_fold(first, |left, right| {
        Ok(combine(Box::new(left), Box::new(right?)))
    })
}

fn parse_mask_type(value: &toml::Value) -> GuardResult<MaskType> {
    if let Some(kind) = value.as_str() {
        return match kind {
            "redact" => Ok(MaskType::Redact),
            "hash_blake3" | "hash" => Ok(MaskType::HashBlake3),
            "email_mask" => Ok(MaskType::EmailMask),
            _ => Err(GuardError::ConfigError(format!(
                "unsupported mask type: {kind}"
            ))),
        };
    }

    let table = value
        .as_table()
        .ok_or_else(|| GuardError::ConfigError("mask_type must be a string or table".to_owned()))?;
    if let Some(truncate) = table.get("truncate") {
        if let Some(n) = truncate.get("n").and_then(toml::Value::as_integer) {
            return Ok(MaskType::Truncate { n: n as usize });
        }
    }
    if let Some(json_mask) = table.get("json_field_mask") {
        if let Some(pattern) = json_mask.get("pattern").and_then(toml::Value::as_str) {
            return Ok(MaskType::JsonFieldMask {
                pattern: pattern.to_owned(),
            });
        }
    }
    Err(GuardError::ConfigError(
        "unsupported mask type table".to_owned(),
    ))
}

fn row_to_policy(row: &sqlx::sqlite::SqliteRow) -> GuardResult<Policy> {
    Ok(Policy {
        id: Uuid::parse_str(&row.try_get::<String, _>("id")?)?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        rules: serde_json::from_str(&row.try_get::<String, _>("rules")?)?,
        priority: row.try_get("priority")?,
        enabled: row.try_get::<i64, _>("enabled")? != 0,
        created_at: from_ms(row.try_get("created_at")?)?,
        updated_at: from_ms(row.try_get("updated_at")?)?,
    })
}

fn from_ms(value: i64) -> GuardResult<DateTime<Utc>> {
    DateTime::from_timestamp_millis(value)
        .ok_or_else(|| GuardError::ConfigError(format!("invalid timestamp millis: {value}")))
}

fn default_enabled() -> bool {
    true
}
