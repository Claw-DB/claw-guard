use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::GuardResult;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MaskType {
    Redact,
    Hash,
    Truncate { max_len: usize },
    EmailMask,
    JsonFieldMask { field_pattern: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaskDirective {
    pub field_pattern: String,
    pub mask_type: MaskType,
}

#[derive(Debug, Default, Clone)]
pub struct MaskingEngine;

impl MaskingEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn apply(value: &mut Value, masks: &[MaskDirective]) -> GuardResult<()> {
        Self::apply_at_path(value, "$", masks)
    }

    fn apply_at_path(value: &mut Value, path: &str, masks: &[MaskDirective]) -> GuardResult<()> {
        for directive in masks {
            if glob_matches(&directive.field_pattern, path) {
                apply_mask_type(value, &directive.mask_type)?;
            }
        }

        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let child_path = format!("{path}.{key}");
                    Self::apply_at_path(child, &child_path, masks)?;
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    let child_path = format!("{path}[{index}]");
                    Self::apply_at_path(child, &child_path, masks)?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}

fn apply_mask_type(value: &mut Value, mask_type: &MaskType) -> GuardResult<()> {
    match mask_type {
        MaskType::Redact => {
            *value = Value::String("[REDACTED]".to_owned());
        }
        MaskType::Hash => {
            let serialized = match value {
                Value::String(string) => string.clone(),
                _ => serde_json::to_string(value)?,
            };
            *value = Value::String(blake3::hash(serialized.as_bytes()).to_hex().to_string());
        }
        MaskType::Truncate { max_len } => {
            if let Some(string) = value.as_str() {
                let truncated = string.chars().take(*max_len).collect::<String>();
                *value = Value::String(truncated);
            }
        }
        MaskType::EmailMask => {
            if let Some(string) = value.as_str() {
                *value = Value::String(mask_email(string));
            }
        }
        MaskType::JsonFieldMask { field_pattern } => {
            let nested_masks = vec![MaskDirective {
                field_pattern: format!("$.{field_pattern}"),
                mask_type: MaskType::Redact,
            }];
            MaskingEngine::apply(value, &nested_masks)?;
        }
    }
    Ok(())
}

fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "[REDACTED]".to_owned();
    };
    let prefix = local.chars().next().unwrap_or('*');
    format!("{prefix}***@{domain}")
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == value {
        return true;
    }

    let mut remaining = value;
    let parts = pattern.split('*').collect::<Vec<_>>();
    if !pattern.starts_with('*') {
        let first = parts.first().copied().unwrap_or_default();
        if !remaining.starts_with(first) {
            return false;
        }
        remaining = &remaining[first.len()..];
    }

    for part in parts.iter().filter(|segment| !segment.is_empty()) {
        let Some(position) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[position + part.len()..];
    }

    pattern.ends_with('*') || remaining.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn applies_all_mask_types() {
        let mut payload = json!({
            "secret": "open",
            "email": "alice@example.com",
            "note": "truncate-me",
            "nested": {"token": "alpha"},
            "hash_me": "value"
        });
        let masks = vec![
            MaskDirective {
                field_pattern: "$.secret".to_owned(),
                mask_type: MaskType::Redact,
            },
            MaskDirective {
                field_pattern: "$.email".to_owned(),
                mask_type: MaskType::EmailMask,
            },
            MaskDirective {
                field_pattern: "$.note".to_owned(),
                mask_type: MaskType::Truncate { max_len: 4 },
            },
            MaskDirective {
                field_pattern: "$.nested".to_owned(),
                mask_type: MaskType::JsonFieldMask {
                    field_pattern: "token".to_owned(),
                },
            },
            MaskDirective {
                field_pattern: "$.hash_me".to_owned(),
                mask_type: MaskType::Hash,
            },
        ];

        MaskingEngine::apply(&mut payload, &masks).expect("masking should succeed");

        assert_eq!(payload["secret"], "[REDACTED]");
        assert_eq!(payload["email"], "a***@example.com");
        assert_eq!(payload["note"], "trun");
        assert_eq!(payload["nested"]["token"], "[REDACTED]");
        assert_ne!(payload["hash_me"], "value");
    }
}
