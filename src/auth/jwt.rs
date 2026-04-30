#![allow(dead_code, unused_variables, unused_imports)]
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::error::{GuardError, GuardResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: Vec<String>,
    pub workspace_id: String,
    pub role: String,
    pub scopes: Vec<String>,
}

pub struct JwtValidator { secret: Vec<u8>, issuer: String, audience: Vec<String> }

impl JwtValidator {
    pub fn new(secret: impl AsRef<[u8]>, issuer: String, audience: Vec<String>) -> Self {
        Self { secret: secret.as_ref().to_vec(), issuer, audience }
    }

    pub fn validate(&self, token: &str) -> GuardResult<Claims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);
        let key = DecodingKey::from_secret(&self.secret);
        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| GuardError::TokenInvalid(e.to_string()))?;
        let now = Utc::now().timestamp();
        if data.claims.exp < now {
            return Err(GuardError::TokenExpired { expired_at: chrono::DateTime::from_timestamp(data.claims.exp, 0).unwrap_or_else(Utc::now) });
        }
        Ok(data.claims)
    }

    pub fn issue(&self, claims: &Claims) -> GuardResult<String> {
        let key = EncodingKey::from_secret(&self.secret);
        encode(&Header::default(), claims, &key)
            .map_err(|e| GuardError::Crypto(e.to_string()))
    }
}
