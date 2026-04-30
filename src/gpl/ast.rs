#![allow(dead_code, unused_variables, unused_imports)]
use crate::policy::model::SensitivityLevel;
use chrono::Weekday;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GplPolicy {
    pub name: String,
    pub version: u32,
    pub rules: Vec<GplRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GplRule {
    pub effect: GplEffect,
    pub conditions: Vec<GplCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GplEffect {
    Allow,
    Deny,
    Redact { fields: Vec<String> },
    Escalate { reason: Option<String> },
    RateLimit { rpm: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GplCondition {
    SubjectRole { value: String, negated: bool },
    SubjectAgent { id: String, negated: bool },
    SubjectScope { scope: String },
    TaskIs { value: String, negated: bool },
    ResourceType { value: String },
    ResourceSensitivity { level: SensitivityLevel },
    ResourceTag { tag: String },
    RiskBelow { threshold: f64 },
    RiskAbove { threshold: f64 },
    TimeBetween { start: (u8, u8), end: (u8, u8) },
    DayIs { day: Weekday },
    MetadataIs { key: String, value: serde_json::Value },
    And(Vec<GplCondition>),
    Or(Vec<GplCondition>),
    Not(Box<GplCondition>),
}
