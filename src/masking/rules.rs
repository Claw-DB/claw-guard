#![allow(dead_code, unused_variables, unused_imports)]
use serde::{Deserialize, Serialize};
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskingRule {
    pub field_pattern: String,
    pub replacement: String,
}

impl MaskingRule {
    pub fn new(field_pattern: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self { field_pattern: field_pattern.into(), replacement: replacement.into() }
    }

    pub fn matches_field(&self, field: &str) -> bool {
        if let Ok(re) = Regex::new(&self.field_pattern) {
            re.is_match(field)
        } else {
            field == self.field_pattern
        }
    }
}
