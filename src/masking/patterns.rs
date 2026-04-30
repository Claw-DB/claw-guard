#![allow(dead_code, unused_variables, unused_imports)]

pub const SSN_PATTERN: &str = r"\d{3}-\d{2}-\d{4}";
pub const EMAIL_PATTERN: &str = r"[^@\s]+@[^@\s]+\.[^@\s]+";
pub const CREDIT_CARD_PATTERN: &str = r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}";

pub fn mask_ssn(value: &str) -> String { "***-**-****".into() }
pub fn mask_email(value: &str) -> String {
    let parts: Vec<&str> = value.splitn(2, '@').collect();
    if parts.len() == 2 { format!("***@{}", parts[1]) } else { "***".into() }
}
pub fn mask_credit_card(value: &str) -> String { "****-****-****-****".into() }
