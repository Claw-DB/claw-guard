#![allow(dead_code, unused_variables, unused_imports)]
use crate::risk::model::{RiskLevel, RiskScore, RiskSignal};
use crate::context::request::AccessRequest;
use crate::config::GuardConfig;
use std::sync::Arc;

pub struct RiskScorer { config: Arc<GuardConfig> }

impl RiskScorer {
    pub fn new(config: Arc<GuardConfig>) -> Self { Self { config } }
    pub fn score(&self, request: &AccessRequest, signals: Vec<RiskSignal>) -> RiskScore {
        let raw = if signals.is_empty() { request.risk_score_hint } else {
            let total_weight: f64 = signals.iter().map(|s| s.weight).sum();
            if total_weight == 0.0 { 0.0 } else { signals.iter().map(|s| s.value * s.weight).sum::<f64>() / total_weight }
        };
        let score = raw.clamp(0.0, 1.0);
        let level = if score >= self.config.risk_critical_threshold { RiskLevel::Critical }
            else if score >= self.config.risk_high_threshold { RiskLevel::High }
            else if score >= 0.5 { RiskLevel::Medium }
            else { RiskLevel::Low };
        RiskScore { score, level, signals }
    }
}
