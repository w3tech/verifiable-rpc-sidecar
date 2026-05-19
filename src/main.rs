use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rpc_attest_sidecar::config::Config;
use rpc_attest_sidecar::proxy::UpstreamClient;
use rpc_attest_sidecar::server::{build_router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    info!(
        listen_addr = %config.listen_addr,
        upstream = %config.upstream_url,
        "starting rpc-attest-sidecar"
    );

    let upstream = UpstreamClient::new(config.upstream_url.clone());
    let app = build_router(AppState { upstream });

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.listen_addr))?;
    axum::serve(listener, app).await.context("serve")?;
    Ok(())
}
