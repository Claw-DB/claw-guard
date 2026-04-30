#![allow(dead_code, unused_variables, unused_imports)]
use crate::audit::entry::AuditLogEntry;
use crate::error::{GuardError, GuardResult};

pub struct AuditChainVerifier;

impl AuditChainVerifier {
    pub fn verify_chain(entries: &[AuditLogEntry]) -> GuardResult<()> {
        for (i, entry) in entries.iter().enumerate() {
            if i == 0 { continue; }
            let prev = &entries[i - 1];
            let prev_bytes = prev.content_bytes();
            let prev_hash: [u8; 32] = *blake3::hash(&prev_bytes).as_bytes();
            if let Some(stored_hash) = &entry.prev_hash {
                if stored_hash != &prev_hash {
                    return Err(GuardError::AuditChainBroken { at_sequence: entry.sequence });
                }
            }
        }
        Ok(())
    }
}
