#![allow(dead_code, unused_variables, unused_imports)]
use serde::{Deserialize, Serialize};
use crate::error::{GuardError, GuardResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimUser { pub id: String, pub user_name: String, pub active: bool, pub roles: Vec<String> }

pub struct ScimHandler;

impl ScimHandler {
    pub fn provision_user(&self, user: ScimUser) -> GuardResult<()> {
        tracing::info!(user_id = %user.id, "SCIM user provisioned");
        Ok(())
    }
    pub fn deprovision_user(&self, user_id: &str) -> GuardResult<()> {
        tracing::info!(user_id, "SCIM user deprovisioned");
        Ok(())
    }
}
