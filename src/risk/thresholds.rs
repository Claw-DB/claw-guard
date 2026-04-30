#![allow(dead_code, unused_variables, unused_imports)]
use crate::risk::model::RiskLevel;

pub struct RiskThresholds { pub high: f64, pub critical: f64 }

impl RiskThresholds {
    pub fn new(high: f64, critical: f64) -> Self { Self { high, critical } }
    pub fn classify(&self, score: f64) -> RiskLevel {
        if score >= self.critical { RiskLevel::Critical }
        else if score >= self.high { RiskLevel::High }
        else if score >= 0.5 { RiskLevel::Medium }
        else { RiskLevel::Low }
    }
}
