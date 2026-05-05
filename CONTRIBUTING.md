# Contributing

## Development Setup

1. Install stable Rust 1.75 or newer.
2. Run `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` before submitting changes.
3. Run `cargo test --all-features` locally.

## Pull Requests

1. Keep changes focused and include tests for behavior changes.
2. Update documentation for public API changes.
3. Do not commit generated artifacts such as `target/`.