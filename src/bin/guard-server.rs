use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

/// Starts the `claw-guard` gRPC server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = claw_guard::GuardConfig::from_env()?;
    let guard = Arc::new(claw_guard::Guard::new(config).await?);
    let bind_addr: SocketAddr = std::env::var("CLAW_GUARD_GRPC_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:50051".to_owned())
        .parse()?;
    claw_guard::grpc::serve(guard, bind_addr).await?;
    Ok(())
}
