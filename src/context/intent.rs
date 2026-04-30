#![allow(dead_code, unused_variables, unused_imports)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct IntentContext {
    pub task_type: Option<String>,
    pub task_description: Option<String>,
    pub intent_confidence: f64,
    pub intent_labels: Vec<String>,
}
