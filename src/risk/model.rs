#![allow(dead_code, unused_variables, unused_imports)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskSignal { pub name: String, pub value: f64, pub weight: f64 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskScore { pub score: f64, pub level: RiskLevel, pub signals: Vec<RiskSignal> }
