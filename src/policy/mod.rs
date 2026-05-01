use std::path::{Path, PathBuf};

use glob::glob;
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use uuid::Uuid;

use crate::error::{GuardError, GuardResult};
use crate::masking::{MaskDirective, MaskType};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyRule {
	AllowIf { condition: Condition },
	DenyIf { condition: Condition },
	MaskField { field_pattern: String, mask_type: MaskType },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Condition {
	TaskMatches(String),
	RoleIn(Vec<String>),
	ScopeContains(String),
	RiskAbove(f64),
	ResourceIs(String),
	And(Box<Condition>, Box<Condition>),
	Or(Box<Condition>, Box<Condition>),
	Not(Box<Condition>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
	Allow,
	Deny { reason: String },
	Mask { fields: Vec<MaskDirective> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvalContext {
	pub agent_id: Uuid,
	pub role: String,
	pub scopes: Vec<String>,
	pub task: String,
	pub resource: String,
	pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredPolicyRule {
	pub rule: PolicyRule,
	pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRecord {
	pub id: Uuid,
	pub name: String,
	pub description: Option<String>,
	pub rules: Vec<StoredPolicyRule>,
	pub priority: i32,
	pub enabled: bool,
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
	name: Option<String>,
	description: Option<String>,
	priority: Option<i32>,
	enabled: Option<bool>,
	rules: Vec<PolicyRuleFile>,
}

#[derive(Debug, Deserialize)]
struct PolicyRuleFile {
	#[serde(rename = "type")]
	rule_type: String,
	condition: Option<toml::Value>,
	reason: Option<String>,
	field_pattern: Option<String>,
	mask_type: Option<toml::Value>,
}

#[derive(Clone)]
pub struct PolicyEngine {
	pool: SqlitePool,
	policy_dir: PathBuf,
}

impl PolicyEngine {
	pub fn new(pool: SqlitePool, policy_dir: impl Into<PathBuf>) -> Self {
		Self {
			pool,
			policy_dir: policy_dir.into(),
		}
	}

	pub async fn evaluate(&self, context: &EvalContext) -> GuardResult<PolicyDecision> {
		let rows = sqlx::query(
			"SELECT id, name, description, rules FROM policies WHERE enabled = 1 ORDER BY priority DESC, created_at DESC",
		)
		.fetch_all(&self.pool)
		.await?;

		for row in rows {
			let policy_name: String = row.try_get("name")?;
			let description: Option<String> = row.try_get("description")?;
			let rules_json: String = row.try_get("rules")?;
			let rules: Vec<StoredPolicyRule> = serde_json::from_str(&rules_json)?;

			for stored_rule in rules {
				match stored_rule.rule {
					PolicyRule::AllowIf { condition } if condition.matches(context) => {
						return Ok(PolicyDecision::Allow);
					}
					PolicyRule::DenyIf { condition } if condition.matches(context) => {
						let reason = stored_rule
							.reason
							.or(description.clone())
							.unwrap_or_else(|| format!("policy {policy_name} denied access"));
						return Ok(PolicyDecision::Deny { reason });
					}
					PolicyRule::MaskField { field_pattern, mask_type } => {
						return Ok(PolicyDecision::Mask {
							fields: vec![MaskDirective {
								field_pattern,
								mask_type,
							}],
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

	pub async fn reload_policies_from_dir(&self) -> GuardResult<usize> {
		if !self.policy_dir.exists() {
			return Ok(0);
		}

		let mut loaded = 0usize;
		let pattern = self.policy_dir.join("*.toml");
		let pattern = pattern.to_string_lossy().to_string();
		for entry in glob(&pattern).map_err(|error| GuardError::PolicyParse(error.to_string()))? {
			let path = entry.map_err(|error| GuardError::PolicyParse(error.to_string()))?;
			self.add_policy_from_file(&path).await?;
			loaded += 1;
		}

		Ok(loaded)
	}

	pub async fn add_policy_from_file(&self, path: &Path) -> GuardResult<PolicyRecord> {
		let source = std::fs::read_to_string(path)?;
		let fallback_name = path
			.file_stem()
			.and_then(|stem| stem.to_str())
			.unwrap_or("policy");
		self.add_policy_from_toml(&source, fallback_name).await
	}

	pub async fn add_policy_from_toml(&self, source: &str, fallback_name: &str) -> GuardResult<PolicyRecord> {
		let parsed: PolicyFile = toml::from_str(source)?;
		let rules = parsed
			.rules
			.into_iter()
			.map(parse_rule)
			.collect::<GuardResult<Vec<_>>>()?;
		let policy = PolicyRecord {
			id: Uuid::new_v4(),
			name: parsed.name.unwrap_or_else(|| fallback_name.to_owned()),
			description: parsed.description,
			rules,
			priority: parsed.priority.unwrap_or_default(),
			enabled: parsed.enabled.unwrap_or(true),
		};
		self.upsert_policy(&policy).await?;
		Ok(policy)
	}

	pub async fn upsert_policy(&self, policy: &PolicyRecord) -> GuardResult<()> {
		let rules = serde_json::to_string(&policy.rules)?;
		sqlx::query(
			"INSERT INTO policies (id, name, description, rules, priority, enabled, created_at, updated_at)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
			 ON CONFLICT(name) DO UPDATE SET
				 description = excluded.description,
				 rules = excluded.rules,
				 priority = excluded.priority,
				 enabled = excluded.enabled,
				 updated_at = CURRENT_TIMESTAMP",
		)
		.bind(policy.id.to_string())
		.bind(&policy.name)
		.bind(&policy.description)
		.bind(rules)
		.bind(policy.priority)
		.bind(policy.enabled)
		.execute(&self.pool)
		.await?;
		Ok(())
	}

	pub async fn list_policies(&self) -> GuardResult<Vec<PolicyRecord>> {
		let rows = sqlx::query(
			"SELECT id, name, description, rules, priority, enabled FROM policies ORDER BY priority DESC, name ASC",
		)
		.fetch_all(&self.pool)
		.await?;

		rows.into_iter()
			.map(|row| {
				let id: String = row.try_get("id")?;
				let rules_json: String = row.try_get("rules")?;
				Ok(PolicyRecord {
					id: Uuid::parse_str(&id)?,
					name: row.try_get("name")?,
					description: row.try_get("description")?,
					rules: serde_json::from_str(&rules_json)?,
					priority: row.try_get("priority")?,
					enabled: row.try_get("enabled")?,
				})
			})
			.collect()
	}

	pub async fn remove_policy(&self, policy_id: Uuid) -> GuardResult<()> {
		let result = sqlx::query("DELETE FROM policies WHERE id = ?1")
			.bind(policy_id.to_string())
			.execute(&self.pool)
			.await?;
		if result.rows_affected() == 0 {
			return Err(GuardError::PolicyNotFound(policy_id.to_string()));
		}
		Ok(())
	}

	pub async fn add_policy(&self, policy: &PolicyRecord) -> GuardResult<()> {
		self.upsert_policy(policy).await
	}
}

impl Condition {
	pub fn matches(&self, context: &EvalContext) -> bool {
		match self {
			Self::TaskMatches(expected) => context.task == *expected,
			Self::RoleIn(roles) => roles.iter().any(|role| role == &context.role),
			Self::ScopeContains(scope) => context.scopes.iter().any(|item| item == scope),
			Self::RiskAbove(threshold) => context.risk_score > *threshold,
			Self::ResourceIs(resource) => context.resource == *resource,
			Self::And(left, right) => left.matches(context) && right.matches(context),
			Self::Or(left, right) => left.matches(context) || right.matches(context),
			Self::Not(inner) => !inner.matches(context),
		}
	}
}

fn parse_rule(rule: PolicyRuleFile) -> GuardResult<StoredPolicyRule> {
	let stored_rule = match rule.rule_type.as_str() {
		"allow_if" => StoredPolicyRule {
			rule: PolicyRule::AllowIf {
				condition: parse_condition(rule.condition.as_ref().ok_or_else(|| {
					GuardError::PolicyParse("allow_if requires condition".to_owned())
				})?)?,
			},
			reason: rule.reason,
		},
		"deny_if" => StoredPolicyRule {
			rule: PolicyRule::DenyIf {
				condition: parse_condition(rule.condition.as_ref().ok_or_else(|| {
					GuardError::PolicyParse("deny_if requires condition".to_owned())
				})?)?,
			},
			reason: rule.reason,
		},
		"mask_field" => StoredPolicyRule {
			rule: PolicyRule::MaskField {
				field_pattern: rule.field_pattern.ok_or_else(|| {
					GuardError::PolicyParse("mask_field requires field_pattern".to_owned())
				})?,
				mask_type: parse_mask_type(rule.mask_type.as_ref().ok_or_else(|| {
					GuardError::PolicyParse("mask_field requires mask_type".to_owned())
				})?)?,
			},
			reason: rule.reason,
		},
		other => {
			return Err(GuardError::PolicyParse(format!(
				"unsupported rule type: {other}"
			)))
		}
	};

	Ok(stored_rule)
}

fn parse_mask_type(value: &toml::Value) -> GuardResult<MaskType> {
	match value {
		toml::Value::String(kind) => match kind.as_str() {
			"redact" => Ok(MaskType::Redact),
			"hash" => Ok(MaskType::Hash),
			"email_mask" => Ok(MaskType::EmailMask),
			other => Err(GuardError::PolicyParse(format!("unsupported mask type: {other}"))),
		},
		toml::Value::Table(table) => {
			if let Some(max_len) = table.get("truncate") {
				let max_len = max_len
					.as_integer()
					.ok_or_else(|| GuardError::PolicyParse("truncate requires integer".to_owned()))?;
				return Ok(MaskType::Truncate {
					max_len: max_len as usize,
				});
			}
			if let Some(pattern) = table.get("json_field_mask") {
				let pattern = pattern.as_str().ok_or_else(|| {
					GuardError::PolicyParse("json_field_mask requires string".to_owned())
				})?;
				return Ok(MaskType::JsonFieldMask {
					field_pattern: pattern.to_owned(),
				});
			}
			Err(GuardError::PolicyParse("unknown mask type table".to_owned()))
		}
		_ => Err(GuardError::PolicyParse("invalid mask_type value".to_owned())),
	}
}

fn parse_condition(value: &toml::Value) -> GuardResult<Condition> {
	let table = value
		.as_table()
		.ok_or_else(|| GuardError::InvalidCondition("condition must be a table".to_owned()))?;

	if let Some(and_value) = table.get("and") {
		return fold_conditions(and_value, Condition::And);
	}
	if let Some(or_value) = table.get("or") {
		return fold_conditions(or_value, Condition::Or);
	}
	if let Some(not_value) = table.get("not") {
		return Ok(Condition::Not(Box::new(parse_condition(not_value)?)));
	}

	let mut parts = Vec::new();
	if let Some(task) = table.get("task_matches") {
		parts.push(Condition::TaskMatches(parse_string(task, "task_matches")?));
	}
	if let Some(roles) = table.get("role_in") {
		parts.push(Condition::RoleIn(parse_string_array(roles, "role_in")?));
	}
	if let Some(scope) = table.get("scope_contains") {
		parts.push(Condition::ScopeContains(parse_string(scope, "scope_contains")?));
	}
	if let Some(risk) = table.get("risk_above") {
		parts.push(Condition::RiskAbove(
			risk.as_float().or_else(|| risk.as_integer().map(|value| value as f64)).ok_or_else(|| {
				GuardError::InvalidCondition("risk_above must be numeric".to_owned())
			})?,
		));
	}
	if let Some(resource) = table.get("resource_is") {
		parts.push(Condition::ResourceIs(parse_string(resource, "resource_is")?));
	}

	combine_with_and(parts)
}

fn fold_conditions<F>(value: &toml::Value, constructor: F) -> GuardResult<Condition>
where
	F: Fn(Box<Condition>, Box<Condition>) -> Condition,
{
	let conditions = value
		.as_array()
		.ok_or_else(|| GuardError::InvalidCondition("logical operator requires array".to_owned()))?
		.iter()
		.map(parse_condition)
		.collect::<GuardResult<Vec<_>>>()?;

	let mut iter = conditions.into_iter();
	let first = iter
		.next()
		.ok_or_else(|| GuardError::InvalidCondition("logical operator requires at least one child".to_owned()))?;
	Ok(iter.fold(first, |acc, condition| constructor(Box::new(acc), Box::new(condition))))
}

fn combine_with_and(parts: Vec<Condition>) -> GuardResult<Condition> {
	let mut iter = parts.into_iter();
	let first = iter
		.next()
		.ok_or_else(|| GuardError::InvalidCondition("condition table was empty".to_owned()))?;
	Ok(iter.fold(first, |acc, condition| Condition::And(Box::new(acc), Box::new(condition))))
}

fn parse_string(value: &toml::Value, field: &str) -> GuardResult<String> {
	value
		.as_str()
		.map(ToOwned::to_owned)
		.ok_or_else(|| GuardError::InvalidCondition(format!("{field} must be a string")))
}

fn parse_string_array(value: &toml::Value, field: &str) -> GuardResult<Vec<String>> {
	let array = value
		.as_array()
		.ok_or_else(|| GuardError::InvalidCondition(format!("{field} must be an array")))?;
	array
		.iter()
		.map(|item| {
			item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
				GuardError::InvalidCondition(format!("{field} entries must be strings"))
			})
		})
		.collect()
}

pub fn build_policy_query<'a>(builder: &'a mut QueryBuilder<'a, Sqlite>, enabled_only: bool) {
	builder.push("SELECT id, name, description, rules, priority, enabled FROM policies");
	if enabled_only {
		builder.push(" WHERE enabled = 1");
	}
	builder.push(" ORDER BY priority DESC, name ASC");
}

#[cfg(test)]
mod tests {
	use super::*;

	fn context() -> EvalContext {
		EvalContext {
			agent_id: Uuid::new_v4(),
			role: "analyst".to_owned(),
			scopes: vec!["read:finance".to_owned(), "tool:planner".to_owned()],
			task: "reporting".to_owned(),
			resource: "finance_records".to_owned(),
			risk_score: 0.72,
		}
	}

	#[test]
	fn condition_task_matches() {
		assert!(Condition::TaskMatches("reporting".to_owned()).matches(&context()));
	}

	#[test]
	fn condition_role_in() {
		assert!(Condition::RoleIn(vec!["analyst".to_owned(), "admin".to_owned()]).matches(&context()));
	}

	#[test]
	fn condition_scope_contains() {
		assert!(Condition::ScopeContains("tool:planner".to_owned()).matches(&context()));
	}

	#[test]
	fn condition_risk_above() {
		assert!(Condition::RiskAbove(0.5).matches(&context()));
	}

	#[test]
	fn condition_resource_is() {
		assert!(Condition::ResourceIs("finance_records".to_owned()).matches(&context()));
	}

	#[test]
	fn condition_and() {
		let condition = Condition::And(
			Box::new(Condition::TaskMatches("reporting".to_owned())),
			Box::new(Condition::ResourceIs("finance_records".to_owned())),
		);
		assert!(condition.matches(&context()));
	}

	#[test]
	fn condition_or() {
		let condition = Condition::Or(
			Box::new(Condition::TaskMatches("scheduling".to_owned())),
			Box::new(Condition::ResourceIs("finance_records".to_owned())),
		);
		assert!(condition.matches(&context()));
	}

	#[test]
	fn condition_not() {
		let condition = Condition::Not(Box::new(Condition::TaskMatches("scheduling".to_owned())));
		assert!(condition.matches(&context()));
	}
}
