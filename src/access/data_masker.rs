#![allow(dead_code, unused_variables, unused_imports)]
use crate::masking::engine::MaskingEngine;
use serde_json::Value;

pub struct DataMasker {
    engine: MaskingEngine,
}

impl DataMasker {
    pub fn new(engine: MaskingEngine) -> Self {
        Self { engine }
    }

    pub fn mask(&self, data: Value) -> Value {
        self.engine.mask_object(data)
    }
}
