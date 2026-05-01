use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = claw_guard::config::GuardConfig::from_env().unwrap_or_else(|e| {
        eprintln!("Config error: {e}");
        std::process::exit(1);
    });

    let guard = Arc::new(claw_guard::guard::Guard::new(config).await?);
    let bind_addr: SocketAddr = std::env::var("CLAW_GUARD_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_owned())
        .parse()?;
    tracing::info!(address = %bind_addr, "claw-guard server starting");
    claw_guard::grpc::serve(guard, bind_addr).await?;
    Ok(())
}
