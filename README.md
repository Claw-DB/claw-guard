# claw-guard

`claw-guard` is the security, session, and policy engine for ClawDB. It provides API key management, JWT-backed sessions, TOML policy loading, risk-aware authorization, batched audit logging, and field masking over a SQLite-backed control plane.

## Features

- API key creation, validation, revocation, and listing with BLAKE3 hashing.
- Session issuance and validation with HS256 JWTs and revocation checks.
- Policy evaluation with allow, deny, and mask rules loaded from SQLite or TOML files.
- Batched audit persistence with filtering and CSV export.
- JSON masking with redact, hash, truncate, email, and nested field masking strategies.
- Optional gRPC service for remote authorization and administration.

## Installation

```toml
[dependencies]
claw-guard = "0.1.2"
```

## Configuration

`GuardConfig::from_env()` reads these variables:

- `CLAW_GUARD_JWT_SECRET` (required)
- `CLAW_GUARD_DB_PATH` (default: `claw_guard.db`)
- `CLAW_GUARD_POLICY_DIR` (optional)
- `CLAW_GUARD_SENSITIVE_RESOURCES` (comma-separated)
- `CLAW_GUARD_AUDIT_FLUSH_INTERVAL_MS` (default: `100`)
- `CLAW_GUARD_AUDIT_BATCH_SIZE` (default: `500`)
- `CLAW_GUARD_BUSINESS_HOURS_START` (default: `8`)
- `CLAW_GUARD_BUSINESS_HOURS_END` (default: `18`)

## Quick Start

```rust
use claw_guard::{Guard, GuardConfig, PolicyDecision};
use secrecy::SecretString;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let guard = Guard::new(GuardConfig {
        db_path: PathBuf::from("claw_guard.db"),
        jwt_secret: SecretString::new("replace-me".to_owned().into_boxed_str()),
        policy_dir: Some(PathBuf::from("./policies")),
        sensitive_resources: vec!["finance_records".to_owned()],
        audit_flush_interval_ms: 100,
        audit_batch_size: 500,
        business_hours_start_hour: 8,
        business_hours_end_hour: 18,
    })
    .await?;

    let session = guard
        .sessions()
        .create_session(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            "admin",
            vec!["tool:*".to_owned()],
            3600,
        )
        .await?;

    match guard.check_access(&session, "read", "users").await? {
        PolicyDecision::Allow => println!("allowed"),
        PolicyDecision::Deny { reason } => println!("denied: {reason}"),
        PolicyDecision::Mask { fields } => println!("mask fields: {fields:?}"),
    }

    Ok(())
}
```

## Policy Files

Policy files support single-policy or multi-policy TOML documents. Example:

```toml
[[policies]]
name = "deny-finance-during-scheduling"
priority = 100

[[policies.rules]]
type = "deny_if"
reason = "Finance data not accessible during scheduling tasks"
[policies.rules.condition]
and = [{ task_matches = "scheduling" }, { resource_is = "finance_records" }]
```

Supported condition operators are `task_matches`, `role_is`, `scope_contains`, `risk_above`, `resource_is`, `workspace_is`, `and`, `or`, and `not`.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## License

Apache-2.0. See `LICENSE`.