# claw-guard

Policy-driven security, session management, and audit enforcement for ClawDB workloads.

claw-guard is a Rust crate and service that evaluates authorization decisions at runtime using role and scope context, task/resource metadata, and configurable risk scoring. It supports allow, deny, and mask outcomes, with durable audit logging and a gRPC interface for external integration.

## What This Crate Provides

- Policy engine with TOML-defined rules (allow, deny, mask)
- Session creation, validation, revocation, and pagination
- Risk-aware access decisions based on action/resource/time-of-day heuristics
- Mask directives for field-level data handling
- Structured audit log writer/reader on SQLite
- gRPC server exposing decisioning and admin APIs

## Install

Add to Cargo.toml:

```toml
[dependencies]
claw-guard = "0.1.1"
```

## Architecture Overview

- Guard: top-level coordinator for policy engine, session manager, and audit components
- PolicyEngine: loads and evaluates policy files from a directory
- SessionManager: issues JWT-backed sessions and validates/revokes them
- AuditWriter/AuditReader: records and queries access events
- gRPC service: wraps the same Guard flows over a network API

## Configuration

Configuration is loaded from environment variables using GuardConfig::from_env().

Required:

- CLAW_GUARD_JWT_SECRET: signing key for HS256 session tokens

Optional:

- CLAW_GUARD_DB_PATH (default: claw_guard.db)
- CLAW_GUARD_POLICY_DIR (default: policies)
- CLAW_GUARD_TLS_CERT_PATH (default: certs/server.crt)
- CLAW_GUARD_TLS_KEY_PATH (default: certs/server.key)
- CLAW_GUARD_SENSITIVE_RESOURCES (comma-separated)
- CLAW_GUARD_AUDIT_FLUSH_INTERVAL_MS (default: 100)
- CLAW_GUARD_AUDIT_BATCH_SIZE (default: 500)
- CLAW_GUARD_RISK_THRESHOLDS_WRITE_WEIGHT (default: 0.25)
- CLAW_GUARD_RISK_THRESHOLDS_DELETE_WEIGHT (default: 0.4)
- CLAW_GUARD_RISK_THRESHOLDS_SENSITIVE_WEIGHT (default: 0.35)
- CLAW_GUARD_RISK_THRESHOLDS_OFF_HOURS_WEIGHT (default: 0.2)
- CLAW_GUARD_RISK_THRESHOLDS_DENY_THRESHOLD (default: 0.9)

## Quick Start (Library)

```rust
use claw_guard::{AccessResult, Guard, GuardConfig, ZeroizeString};
use std::path::PathBuf;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let config = GuardConfig {
		db_path: "claw_guard.db".to_string(),
		jwt_secret: ZeroizeString::new("replace-me"),
		policy_dir: PathBuf::from("./policies"),
		tls_cert_path: PathBuf::from("./certs/server.crt"),
		tls_key_path: PathBuf::from("./certs/server.key"),
		risk_thresholds: Default::default(),
		sensitive_resources: vec!["finance_records".to_string()],
		audit_flush_interval_ms: 100,
		audit_batch_size: 500,
	};

	let guard = Guard::new(config).await?;

	let session = guard
		.session_manager
		.create_session(Uuid::new_v4(), "analyst", vec!["tool:*".into()], 3600)
		.await?;

	match guard
		.check_access_with_task(&session.token, "read", "customer_records", "reporting")
		.await?
	{
		AccessResult::Allowed => println!("allowed"),
		AccessResult::Denied { reason } => println!("denied: {reason}"),
		AccessResult::Masked { fields } => println!("masked fields: {}", fields.len()),
	}

	Ok(())
}
```

## Policy Format (TOML)

Example policy file:

```toml
name = "base"
description = "baseline guard policy"
priority = 100

[[rules]]
type = "allow_if"
condition = { role_in = ["analyst"], resource_is = "docs" }

[[rules]]
type = "deny_if"
condition = { task_matches = "scheduling", resource_is = "finance_records" }
reason = "finance blocked during scheduling"

[[rules]]
type = "mask_field"
field_pattern = "$.ssn"
mask_type = "redact"
```

## gRPC Server

The crate ships with a binary:

```bash
cargo run --bin guard-server
```

Service methods (see proto/guard.proto):

- CheckAccess
- CreateSession
- ValidateSession
- RevokeSession
- AddPolicy
- ListPolicies
- RemovePolicy
- QueryAuditLog

TLS cert and key paths are read from GuardConfig.

## Data Model and Persistence

- Uses SQLite via sqlx
- Applies migrations from migrations/
- Stores sessions, roles, policies, and audit events
- Persists policy metadata while allowing filesystem policy loading and reload

## Local Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

For benchmark runs:

```bash
cargo bench
```

## Versioning

Current version: 0.1.1

## License

MIT. See LICENSE.
