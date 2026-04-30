#![allow(dead_code, unused_variables, unused_imports)]
use crate::risk::model::RiskSignal;
use crate::context::request::AccessRequest;

pub fn extract_signals(request: &AccessRequest) -> Vec<RiskSignal> {
    let mut signals = Vec::new();
    if request.risk_score_hint > 0.0 {
        signals.push(RiskSignal { name: "hint".into(), value: request.risk_score_hint, weight: 1.0 });
    }
    if request.action.eq_ignore_ascii_case("delete") || request.action.eq_ignore_ascii_case("admin") {
        signals.push(RiskSignal { name: "sensitive_action".into(), value: 0.6, weight: 0.8 });
    }
    signals
}
