#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::GuardResult;
use serde_json::Value;

pub struct ToolGuard {
    blocked_tools: Vec<String>,
}

impl ToolGuard {
    pub fn new(blocked_tools: Vec<String>) -> Self {
        Self { blocked_tools }
    }

    pub fn is_tool_permitted(&self, tool_name: &str) -> bool {
        !self.blocked_tools.iter().any(|t| t.eq_ignore_ascii_case(tool_name))
    }

    pub fn sanitize_input(&self, tool_name: &str, input: Value) -> GuardResult<Value> {
        Ok(input)
    }
}
