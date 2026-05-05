use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::GuardResult;

/// Masking strategy applied to a matched field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaskType {
    /// Replaces the value with `[REDACTED]`.
    Redact,
    /// Replaces the value with a BLAKE3 hex digest.
    HashBlake3,
    /// Keeps the first `n` characters.
    Truncate { n: usize },
    /// Keeps the first character of the local part and preserves the domain.
    EmailMask,
    /// Redacts matching keys inside a JSON object.
    JsonFieldMask { pattern: String },
}

/// A field mask directive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaskDirective {
    /// Path or glob-like field pattern.
    pub field_pattern: String,
    /// Mask type to apply.
    pub mask_type: MaskType,
}

/// Applies configured masking directives to JSON values.
#[derive(Debug, Clone, Default)]
pub struct MaskingEngine;

impl MaskingEngine {
    /// Creates a new masking engine.
    pub fn new() -> Self {
        Self
    }

    /// Applies mask directives to a JSON value in place.
    pub fn apply(value: &mut Value, masks: &[MaskDirective]) -> GuardResult<()> {
        apply_recursive(value, "$", masks)
    }
}

fn apply_recursive(value: &mut Value, path: &str, masks: &[MaskDirective]) -> GuardResult<()> {
    for directive in masks {
        if matches_pattern(&directive.field_pattern, path) {
            apply_mask(value, &directive.mask_type)?;
        }
    }

    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let child_path = format!("{path}.{key}");
                apply_recursive(child, &child_path, masks)?;
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                let child_path = format!("{path}[{index}]");
                apply_recursive(child, &child_path, masks)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn apply_mask(value: &mut Value, mask_type: &MaskType) -> GuardResult<()> {
    match mask_type {
        MaskType::Redact => *value = Value::String("[REDACTED]".to_owned()),
        MaskType::HashBlake3 => {
            let raw = match value {
                Value::String(inner) => inner.clone(),
                _ => serde_json::to_string(value)?,
            };
            *value = Value::String(blake3::hash(raw.as_bytes()).to_hex().to_string());
        }
        MaskType::Truncate { n } => {
            if let Some(inner) = value.as_str() {
                *value = Value::String(inner.chars().take(*n).collect());
            }
        }
        MaskType::EmailMask => {
            if let Some(inner) = value.as_str() {
                *value = Value::String(mask_email(inner));
            }
        }
        MaskType::JsonFieldMask { pattern } => {
            redact_nested_fields(value, pattern);
        }
    }

    Ok(())
}

fn redact_nested_fields(value: &mut Value, pattern: &str) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if matches_pattern(pattern, key) {
                    *child = Value::String("[REDACTED]".to_owned());
                } else {
                    redact_nested_fields(child, pattern);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_nested_fields(item, pattern);
            }
        }
        _ => {}
    }
}

fn mask_email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('*');
            format!("{first}***@{domain}")
        }
        None => "[REDACTED]".to_owned(),
    }
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }

    let mut remainder = value;
    let parts = pattern.split('*').filter(|part| !part.is_empty());
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let mut first = true;

    for part in parts {
        if first && anchored_start {
            if !remainder.starts_with(part) {
                return false;
            }
            remainder = &remainder[part.len()..];
        } else if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
        } else {
            return false;
        }
        first = false;
    }

    !anchored_end || remainder.is_empty()
}
