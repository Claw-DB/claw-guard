#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::GuardResult;
use serde_json::Value;

pub struct RowFilter {
    denied_fields: Vec<String>,
}

impl RowFilter {
    pub fn new(denied_fields: Vec<String>) -> Self {
        Self { denied_fields }
    }

    pub fn filter_row(&self, mut row: Value) -> Value {
        if let Value::Object(ref mut map) = row {
            for field in &self.denied_fields {
                map.remove(field);
            }
        }
        row
    }
}
