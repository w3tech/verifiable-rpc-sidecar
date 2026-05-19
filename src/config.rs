use std::net::SocketAddr;

use clap::Parser;

use crate::signing::parse_chain_id_hex;

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Verifiable RPC sidecar — see README.md")]
pub struct Config {
    /// Address the sidecar listens on. Plain HTTP only — no TLS listener (DEC-06 / C1).
    #[arg(long, env = "SIDECAR_LISTEN_ADDR", default_value = "0.0.0.0:8545")]
    pub listen_addr: SocketAddr,

    /// Upstream EVM JSON-RPC URL. Plain HTTP — co-located inside the CVM (DEC-05).
    #[arg(long, env = "SIDECAR_UPSTREAM_URL")]
    pub upstream_url: String,

    /// EVM chain id mixed into the SPEC-04 signing pre-image. Accepts decimal
    /// or `0x`-prefixed hex.
    #[arg(long, env = "SIDECAR_CHAIN_ID", value_parser = parse_chain_id_hex)]
    pub chain_id: u64,

    /// Path to the dstack-guest-agent Unix socket. Defaults to
    /// `/var/run/dstack.sock`. Override via `--dstack-endpoint`
    /// or `DSTACK_SIMULATOR_ENDPOINT` for the Phala local simulator.
    #[arg(long, env = "DSTACK_SIMULATOR_ENDPOINT")]
    pub dstack_endpoint: Option<String>,

    /// Key derivation path passed to dstack `get_key`. The version segment
    /// (`/v1`) closes pitfall C5 — keys cannot be reused across sidecar
    /// versions or chains.
    #[arg(long, env = "SIDECAR_KEY_PATH", default_value = "rpc-sign/v1")]
    pub key_path: String,

    /// Optional `purpose` argument passed to dstack `get_key`.
    #[arg(long, env = "SIDECAR_KEY_PURPOSE")]
    pub key_purpose: Option<String>,
}
