#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::GuardResult;
use serde_json::Value;

pub type HookFn = Box<dyn Fn(&Value) -> GuardResult<()> + Send + Sync>;

pub struct HookRegistry { hooks: Vec<HookFn> }

impl HookRegistry {
    pub fn new() -> Self { Self { hooks: Vec::new() } }
    pub fn register(&mut self, hook: HookFn) { self.hooks.push(hook); }
    pub fn fire(&self, event: &Value) -> GuardResult<()> {
        for hook in &self.hooks { hook(event)?; }
        Ok(())
    }
}
