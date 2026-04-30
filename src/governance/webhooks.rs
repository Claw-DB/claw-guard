#![allow(dead_code, unused_variables, unused_imports)]
use reqwest::Client;
use serde_json::Value;
use crate::error::{GuardError, GuardResult};

pub struct WebhookDelivery { client: Client, url: String, max_retries: u32 }

impl WebhookDelivery {
    pub fn new(url: String, max_retries: u32) -> Self {
        Self { client: Client::new(), url, max_retries }
    }

    pub async fn deliver(&self, payload: &Value) -> GuardResult<()> {
        for attempt in 0..=self.max_retries {
            let result = self.client.post(&self.url).json(payload).send().await;
            match result {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(_) if attempt == self.max_retries => {
                    return Err(GuardError::WebhookDeliveryFailed { url: self.url.clone(), attempts: self.max_retries + 1 });
                }
                Err(_) if attempt == self.max_retries => {
                    return Err(GuardError::WebhookDeliveryFailed { url: self.url.clone(), attempts: self.max_retries + 1 });
                }
                _ => { tokio::time::sleep(std::time::Duration::from_millis(500 * (attempt as u64 + 1))).await; }
            }
        }
        Ok(())
    }
}
