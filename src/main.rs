use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use rpc_attest_sidecar::config::Config;
use rpc_attest_sidecar::dstack::DstackClient;
use rpc_attest_sidecar::proxy::UpstreamClient;
use rpc_attest_sidecar::server::{build_router, AppState};
use rpc_attest_sidecar::signing::SigningState;

const FAIL_FAST_DEADLINE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    info!(
        listen_addr = %config.listen_addr,
        upstream = %config.upstream_url,
        chain_id = config.chain_id,
        key_derivation_path = %config.key_path,
        dstack_endpoint = ?config.dstack_endpoint,
        "starting rpc-attest-sidecar"
    );

    let signing = match derive_signing_state(&config).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = ?e, "key derivation failed — aborting");
            sleep_until_deadline().await;
            std::process::exit(2);
        }
    };
    info!(
        signing_pubkey = %signing.pubkey_hex(),
        key_derivation_path = %config.key_path,
        "signing key derived"
    );

    let upstream = UpstreamClient::new(config.upstream_url.clone());
    let app = build_router(AppState { upstream, signing });

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("bind {}", config.listen_addr))?;

    info!("listening on {}", config.listen_addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve")?;

    info!("shutdown complete — secret zeroized");
    Ok(())
}

async fn derive_signing_state(config: &Config) -> Result<SigningState> {
    let dstack = DstackClient::new(config.dstack_endpoint.as_deref());
    info!(socket = ?dstack.socket_path(), "contacting dstack-guest-agent");
    let resp = dstack
        .get_key(Some(&config.key_path), config.key_purpose.as_deref())
        .await
        .context("dstack get_key")?;
    let bytes = resp.decode_key().context("hex-decode dstack key")?;
    SigningState::from_dstack_bytes(&bytes, config.chain_id)
}

/// Block for up to FAIL_FAST_DEADLINE so the operator can see the failure log
/// before the process exits — and so the exit happens promptly (≤5s) per the
/// Phase 6 acceptance criterion.
async fn sleep_until_deadline() {
    sleep(FAIL_FAST_DEADLINE).await;
}

/// Drains in-flight requests on SIGINT / SIGTERM. When this future resolves the
/// signing secret is dropped along with AppState — ZeroizeOnDrop in
/// `ed25519_dalek::SigningKey` clears the bytes from memory.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => info!("SIGINT received"),
        _ = terminate => info!("SIGTERM received"),
    }
    info!("draining in-flight requests");
}
