#![allow(dead_code, unused_variables, unused_imports)]
use crate::context::request::AccessRequest;
use crate::context::EvaluationContext;
use chrono::{DateTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub version: u32,
    pub workspace_id: Uuid,
    pub rules: Vec<PolicyRule>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub description: Option<String>,
    pub source_hash: [u8; 32],
}

impl Policy {
    pub fn rule_count(&self) -> usize { self.rules.len() }
    pub fn active_rules(&self) -> impl Iterator<Item = &PolicyRule> { self.rules.iter() }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRule {
    pub id: Uuid,
    pub effect: PolicyEffect,
    pub priority: i32,
    pub subject: SubjectMatcher,
    pub action: ActionMatcher,
    pub resource: ResourceMatcher,
    pub conditions: Vec<PolicyCondition>,
    pub description: Option<String>,
}

impl PolicyRule {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.subject.matches(req) && self.action.matches(req) && self.resource.matches(req)
    }

    pub fn priority_order(&self) -> (i32, u8) {
        let deny_bonus: u8 = match &self.effect { PolicyEffect::Deny => 1, _ => 0 };
        (self.priority, deny_bonus)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Redact { fields: Vec<String> },
    Escalate { reason: String },
    RateLimit { requests_per_minute: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SubjectMatcher {
    pub role: Option<String>,
    pub agent_id: Option<Uuid>,
    pub task_type: Option<String>,
    pub workspace_id: Option<Uuid>,
}

impl SubjectMatcher {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        if let Some(role) = &self.role { if &req.role != role { return false; } }
        if let Some(agent_id) = &self.agent_id { if &req.agent_id != agent_id { return false; } }
        if let Some(task_type) = &self.task_type { if req.task_type.as_deref() != Some(task_type.as_str()) { return false; } }
        if let Some(ws) = &self.workspace_id { if &req.workspace_id != ws { return false; } }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionType { Read, Write, Delete, Execute, Admin, Any }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionMatcher {
    pub action_type: ActionType,
    pub tool_names: Option<Vec<String>>,
}

impl ActionMatcher {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        match &self.action_type {
            ActionType::Any => true,
            ActionType::Read => req.action.eq_ignore_ascii_case("read"),
            ActionType::Write => req.action.eq_ignore_ascii_case("write"),
            ActionType::Delete => req.action.eq_ignore_ascii_case("delete"),
            ActionType::Execute => req.action.eq_ignore_ascii_case("execute"),
            ActionType::Admin => req.action.eq_ignore_ascii_case("admin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel { Public, Internal, Confidential, Restricted }

impl std::str::FromStr for SensitivityLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "public" => Ok(SensitivityLevel::Public),
            "internal" => Ok(SensitivityLevel::Internal),
            "confidential" => Ok(SensitivityLevel::Confidential),
            "restricted" => Ok(SensitivityLevel::Restricted),
            other => Err(format!("unknown sensitivity level: {other}")),
        }
    }
}

impl std::fmt::Display for SensitivityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SensitivityLevel::Public => "public",
            SensitivityLevel::Internal => "internal",
            SensitivityLevel::Confidential => "confidential",
            SensitivityLevel::Restricted => "restricted",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceMatcher {
    pub entity_type: Option<String>,
    pub entity_ids: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub sensitivity: Option<SensitivityLevel>,
}

impl ResourceMatcher {
    pub fn matches(&self, req: &AccessRequest) -> bool {
        if let Some(entity_type) = &self.entity_type {
            if req.resource_type.as_deref() != Some(entity_type.as_str()) { return false; }
        }
        if let Some(ids) = &self.entity_ids {
            if !ids.is_empty() {
                if !req.resource_ids.iter().any(|rid| ids.contains(rid)) { return false; }
            }
        }
        if let Some(required_tags) = &self.tags {
            for tag in required_tags {
                if !req.resource_tags.contains(tag) { return false; }
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PolicyCondition {
    TimeWindow { start_hour: u8, end_hour: u8, days: Vec<Weekday> },
    TaskIs { task_types: Vec<String> },
    RiskBelow { threshold: f64 },
    RiskAbove { threshold: f64 },
    ScopeContains { scope: String },
    MetadataMatch { key: String, value: serde_json::Value },
    Not(Box<PolicyCondition>),
    And(Vec<PolicyCondition>),
    Or(Vec<PolicyCondition>),
}

impl PolicyCondition {
    pub fn evaluate(&self, ctx: &EvaluationContext) -> bool {
        match self {
            PolicyCondition::TimeWindow { start_hour, end_hour, days } => {
                let hour = ctx.environment.current_time.format("%H").to_string().parse::<u8>().unwrap_or(0);
                let in_window = hour >= *start_hour && hour < *end_hour;
                let day_ok = days.is_empty() || days.contains(&ctx.environment.current_day);
                in_window && day_ok
            }
            PolicyCondition::TaskIs { task_types } => {
                ctx.intent.task_type.as_ref().map(|t| task_types.contains(t)).unwrap_or(false)
            }
            PolicyCondition::RiskBelow { threshold } => ctx.risk_score < *threshold,
            PolicyCondition::RiskAbove { threshold } => ctx.risk_score > *threshold,
            PolicyCondition::ScopeContains { scope } => ctx.request.scopes.contains(scope),
            PolicyCondition::MetadataMatch { key, value } => ctx.request.metadata.get(key).map(|v| v == value).unwrap_or(false),
            PolicyCondition::Not(inner) => !inner.evaluate(ctx),
            PolicyCondition::And(conditions) => conditions.iter().all(|c| c.evaluate(ctx)),
            PolicyCondition::Or(conditions) => conditions.iter().any(|c| c.evaluate(ctx)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AccessDecision {
    Allow,
    Deny { reason: String, rule_id: Option<Uuid> },
    Redact { fields: Vec<String>, reason: String },
    Escalate { reason: String },
    RateLimit { retry_after_ms: u64 },
}

impl AccessDecision {
    pub fn is_permitted(&self) -> bool {
        matches!(self, AccessDecision::Allow | AccessDecision::Redact { .. })
    }
}
