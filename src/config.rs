use std::net::SocketAddr;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Verifiable RPC sidecar — see README.md")]
pub struct Config {
    /// Address the sidecar listens on. Plain HTTP only — no TLS listener (DEC-06 / C1).
    #[arg(long, env = "SIDECAR_LISTEN_ADDR", default_value = "0.0.0.0:8545")]
    pub listen_addr: SocketAddr,

    /// Upstream EVM JSON-RPC URL. Plain HTTP — co-located inside the CVM (DEC-05).
    #[arg(long, env = "SIDECAR_UPSTREAM_URL")]
    pub upstream_url: String,
}
