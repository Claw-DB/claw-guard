#![allow(dead_code, unused_variables, unused_imports)]
use chrono::{DateTime, Datelike, Utc, Weekday};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentContext {
    pub current_time: DateTime<Utc>,
    pub current_day: Weekday,
    pub source_ip: Option<String>,
    pub region: Option<String>,
    pub is_trusted_network: bool,
}

impl Default for EnvironmentContext {
    fn default() -> Self {
        let now = Utc::now();
        let weekday = now.weekday();
        Self {
            current_time: now,
            current_day: weekday,
            source_ip: None,
            region: None,
            is_trusted_network: false,
        }
    }
}
