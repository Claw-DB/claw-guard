#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{GuardError, GuardResult};

pub struct SamlProcessor;

impl SamlProcessor {
    pub fn validate_assertion(&self, _assertion_xml: &str) -> GuardResult<SamlClaims> {
        Err(GuardError::SamlError("SAML validation not implemented".into()))
    }
}

#[derive(Debug, Clone)]
pub struct SamlClaims {
    pub subject: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}
