#![allow(dead_code, unused_variables, unused_imports)]
use pest::iterators::Pair;
use pest::Parser as PestParser;
use pest_derive::Parser;

use crate::error::{GuardError, GuardResult};
use crate::gpl::ast::{GplCondition, GplEffect, GplPolicy, GplRule};
use crate::policy::model::SensitivityLevel;

#[derive(Parser)]
#[grammar = "gpl/guard.pest"]
pub struct PestGplParser;

pub struct GplParser;

impl GplParser {
    pub fn parse(source: &str) -> GuardResult<GplPolicy> {
        let pairs = PestGplParser::parse(Rule::policy, source).map_err(|e| {
            let (line, col) = match e.line_col {
                pest::error::LineColLocation::Pos((l, c)) => (l, c),
                pest::error::LineColLocation::Span((l, c), _) => (l, c),
            };
            GuardError::GplParseError(format!("{}:{}: {}", line, col, e))
        })?;

        let policy_pair = pairs.into_iter().next().ok_or_else(|| {
            GuardError::GplParseError("empty parse result".into())
        })?;

        Self::parse_policy(policy_pair)
    }

    fn parse_policy(pair: Pair<Rule>) -> GuardResult<GplPolicy> {
        let mut inner = pair.into_inner();
        let name_pair = inner.next().ok_or_else(|| GuardError::GplParseError("missing policy name".into()))?;
        let name = Self::parse_string_lit(name_pair);

        let mut version = 1u32;
        let mut rules = Vec::new();

        for item in inner {
            match item.as_rule() {
                Rule::integer_lit => { version = item.as_str().parse().unwrap_or(1); }
                Rule::rule_block => { rules.push(Self::parse_rule_block(item)?); }
                Rule::EOI => {}
                _ => {}
            }
        }

        Ok(GplPolicy { name, version, rules })
    }

    fn parse_rule_block(pair: Pair<Rule>) -> GuardResult<GplRule> {
        let mut inner = pair.into_inner();
        let effect_pair = inner.next().ok_or_else(|| GuardError::GplParseError("missing effect".into()))?;
        let effect = Self::parse_effect(effect_pair)?;

        let mut conditions = Vec::new();
        for item in inner {
            if item.as_rule() == Rule::condition {
                conditions.push(Self::parse_condition(item)?);
            }
        }

        Ok(GplRule { effect, conditions })
    }

    pub fn parse_effect(pair: Pair<Rule>) -> GuardResult<GplEffect> {
        let text = pair.as_str().trim();
        let mut inner = pair.into_inner();
        if text.starts_with("allow") {
            Ok(GplEffect::Allow)
        } else if text.starts_with("deny") {
            Ok(GplEffect::Deny)
        } else if text.starts_with("redact") {
            let mut fields = Vec::new();
            for p in inner {
                if p.as_rule() == Rule::string_lit {
                    fields.push(Self::parse_string_lit(p));
                }
            }
            Ok(GplEffect::Redact { fields })
        } else if text.starts_with("escalate") {
            let reason = inner.next().map(|p| Self::parse_string_lit(p));
            Ok(GplEffect::Escalate { reason })
        } else if text.starts_with("rate_limit") {
            let rpm = inner.next().map(|p| p.as_str().parse::<u32>().unwrap_or(0)).unwrap_or(0);
            Ok(GplEffect::RateLimit { rpm })
        } else {
            Err(GuardError::GplParseError(format!("unknown effect: {text}")))
        }
    }

    pub fn parse_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let inner_pair = pair.into_inner().next().ok_or_else(|| GuardError::GplParseError("empty condition".into()))?;
        Self::parse_condition_inner(inner_pair)
    }

    fn parse_condition_inner(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        match pair.as_rule() {
            Rule::subject_condition => Self::parse_subject_condition(pair),
            Rule::task_condition => Self::parse_task_condition(pair),
            Rule::resource_condition => Self::parse_resource_condition(pair),
            Rule::risk_condition => Self::parse_risk_condition(pair),
            Rule::time_condition => Self::parse_time_condition(pair),
            Rule::metadata_condition => Self::parse_metadata_condition(pair),
            Rule::logical_condition => Self::parse_logical_condition(pair),
            _ => Err(GuardError::GplParseError(format!("unknown condition rule: {text}"))),
        }
    }

    fn parse_subject_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let mut parts = pair.into_inner();
        if text.starts_with("subject role") {
            let negated = text.contains("is not");
            let val = parts.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
            Ok(GplCondition::SubjectRole { value: val, negated })
        } else if text.starts_with("subject agent") {
            let negated = text.contains("is not");
            let val = parts.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
            Ok(GplCondition::SubjectAgent { id: val, negated })
        } else if text.starts_with("subject scope") {
            let scope = parts.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
            Ok(GplCondition::SubjectScope { scope })
        } else {
            Err(GuardError::GplParseError(format!("unknown subject condition: {text}")))
        }
    }

    fn parse_task_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let negated = text.contains("is not");
        let val = pair.into_inner().find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
        Ok(GplCondition::TaskIs { value: val, negated })
    }

    fn parse_resource_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let mut inner = pair.into_inner();
        if text.starts_with("resource type") {
            let val = inner.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
            Ok(GplCondition::ResourceType { value: val })
        } else if text.starts_with("resource sensitivity") {
            let level_str = inner.find(|p| p.as_rule() == Rule::sensitivity_level).map(|p| p.as_str().to_owned()).unwrap_or_default();
            let level: SensitivityLevel = level_str.parse().map_err(|e: String| GuardError::GplParseError(e))?;
            Ok(GplCondition::ResourceSensitivity { level })
        } else if text.starts_with("resource tag") {
            let tag = inner.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
            Ok(GplCondition::ResourceTag { tag })
        } else {
            Err(GuardError::GplParseError(format!("unknown resource condition: {text}")))
        }
    }

    fn parse_risk_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let val = pair.into_inner().find(|p| p.as_rule() == Rule::float_lit).map(|p| p.as_str().parse::<f64>().unwrap_or(0.0)).unwrap_or(0.0);
        if text.starts_with("risk below") {
            Ok(GplCondition::RiskBelow { threshold: val })
        } else {
            Ok(GplCondition::RiskAbove { threshold: val })
        }
    }

    fn parse_time_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let mut inner = pair.into_inner();
        if text.starts_with("time between") {
            let start_str = inner.find(|p| p.as_rule() == Rule::time_lit).map(|p| p.as_str().to_owned()).unwrap_or_default();
            let end_str = inner.find(|p| p.as_rule() == Rule::time_lit).map(|p| p.as_str().to_owned()).unwrap_or_default();
            let start = Self::parse_time_lit(&start_str);
            let end = Self::parse_time_lit(&end_str);
            Ok(GplCondition::TimeBetween { start, end })
        } else {
            let day_str = inner.find(|p| p.as_rule() == Rule::weekday).map(|p| p.as_str().to_owned()).unwrap_or_default();
            let day = Self::parse_weekday(&day_str);
            Ok(GplCondition::DayIs { day })
        }
    }

    fn parse_metadata_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let mut inner = pair.into_inner();
        let key = inner.find(|p| p.as_rule() == Rule::identifier).map(|p| p.as_str().to_owned()).unwrap_or_default();
        let val_str = inner.find(|p| p.as_rule() == Rule::string_lit).map(Self::parse_string_lit).unwrap_or_default();
        let value = serde_json::Value::String(val_str);
        Ok(GplCondition::MetadataIs { key, value })
    }

    fn parse_logical_condition(pair: Pair<Rule>) -> GuardResult<GplCondition> {
        let text = pair.as_str().trim();
        let mut inner = pair.into_inner();
        if text.starts_with("not") {
            let inner_cond = inner.next().ok_or_else(|| GuardError::GplParseError("missing not target".into()))?;
            let cond = Self::parse_condition(inner_cond)?;
            Ok(GplCondition::Not(Box::new(cond)))
        } else if text.starts_with("and") {
            let mut conds = Vec::new();
            for p in inner {
                if p.as_rule() == Rule::condition { conds.push(Self::parse_condition(p)?); }
            }
            Ok(GplCondition::And(conds))
        } else {
            let mut conds = Vec::new();
            for p in inner {
                if p.as_rule() == Rule::condition { conds.push(Self::parse_condition(p)?); }
            }
            Ok(GplCondition::Or(conds))
        }
    }

    fn parse_string_lit(pair: Pair<Rule>) -> String {
        let s = pair.as_str();
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            s[1..s.len()-1].to_owned()
        } else {
            s.to_owned()
        }
    }

    fn parse_time_lit(s: &str) -> (u8, u8) {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        let h = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let m = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        (h, m)
    }

    fn parse_weekday(s: &str) -> chrono::Weekday {
        match s.to_ascii_lowercase().as_str() {
            "monday" => chrono::Weekday::Mon,
            "tuesday" => chrono::Weekday::Tue,
            "wednesday" => chrono::Weekday::Wed,
            "thursday" => chrono::Weekday::Thu,
            "friday" => chrono::Weekday::Fri,
            "saturday" => chrono::Weekday::Sat,
            _ => chrono::Weekday::Sun,
        }
    }
}
