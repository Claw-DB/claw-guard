#![allow(dead_code, unused_variables, unused_imports)]
use crate::masking::rules::MaskingRule;
use serde_json::Value;

pub struct MaskingEngine { rules: Vec<MaskingRule> }

impl MaskingEngine {
    pub fn new(rules: Vec<MaskingRule>) -> Self { Self { rules } }

    pub fn mask_value(&self, field: &str, value: &Value) -> Value {
        for rule in &self.rules {
            if rule.matches_field(field) {
                return Value::String(rule.replacement.clone());
            }
        }
        value.clone()
    }

    pub fn mask_object(&self, obj: Value) -> Value {
        if let Value::Object(mut map) = obj {
            for key in map.keys().cloned().collect::<Vec<_>>() {
                let v = map[&key].clone();
                map.insert(key.clone(), self.mask_value(&key, &v));
            }
            Value::Object(map)
        } else {
            obj
        }
    }
}
