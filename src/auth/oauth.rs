#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{GuardError, GuardResult};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub sub: Option<String>,
    pub exp: Option<i64>,
    pub scope: Option<String>,
}

pub struct OAuthIntrospector { client: Client, endpoint: String, client_id: String, client_secret: String }

impl OAuthIntrospector {
    pub fn new(endpoint: String, client_id: String, client_secret: String) -> Self {
        Self { client: Client::new(), endpoint, client_id, client_secret }
    }

    pub async fn introspect(&self, token: &str) -> GuardResult<IntrospectionResponse> {
        let resp = self.client.post(&self.endpoint)
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token)])
            .send().await
            .map_err(|e| GuardError::TokenInvalid(e.to_string()))?
            .json::<IntrospectionResponse>().await
            .map_err(|e| GuardError::TokenInvalid(e.to_string()))?;
        if !resp.active { return Err(GuardError::TokenInvalid("token is inactive".into())); }
        Ok(resp)
    }
}
