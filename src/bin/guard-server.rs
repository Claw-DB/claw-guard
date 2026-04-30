#![allow(dead_code, unused_variables, unused_imports)]
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    tracing::info!("claw-guard server starting");

    let config = claw_guard::config::GuardConfig::from_env().unwrap_or_else(|e| {
        eprintln!("Config error: {e}");
        std::process::exit(1);
    });

    tracing::info!(port = config.grpc_port, "guard-server ready");
    Ok(())
}
