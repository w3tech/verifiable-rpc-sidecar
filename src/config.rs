use std::net::SocketAddr;

use clap::Parser;

use crate::signing::parse_chain_id_hex;

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Verifiable RPC sidecar — see README.md")]
pub struct Config {
    /// Address the sidecar listens on. Plain HTTP only — no TLS listener.
    #[arg(long, env = "SIDECAR_LISTEN_ADDR", default_value = "0.0.0.0:8545")]
    pub listen_addr: SocketAddr,

    /// Upstream EVM JSON-RPC URL. Plain HTTP — co-located inside the CVM.
    #[arg(long, env = "SIDECAR_UPSTREAM_URL")]
    pub upstream_url: String,

    /// EVM chain id mixed into the signing pre-image. Accepts decimal
    /// or `0x`-prefixed hex.
    #[arg(long, env = "SIDECAR_CHAIN_ID", value_parser = parse_chain_id_hex)]
    pub chain_id: u64,

    /// Path to the dstack-guest-agent Unix socket. Defaults to
    /// `/var/run/dstack.sock`. Override via `--dstack-endpoint`
    /// or `DSTACK_SIMULATOR_ENDPOINT` for the Phala local simulator.
    #[arg(long, env = "DSTACK_SIMULATOR_ENDPOINT")]
    pub dstack_endpoint: Option<String>,

    /// Key derivation path passed to dstack `get_key`. The version segment
    /// (`/v1`) prevents key reuse across sidecar versions or chains.
    #[arg(long, env = "SIDECAR_KEY_PATH", default_value = "rpc-sign/v1")]
    pub key_path: String,

    /// Optional `purpose` argument passed to dstack `get_key`.
    #[arg(long, env = "SIDECAR_KEY_PURPOSE")]
    pub key_purpose: Option<String>,

    /// Maximum request and upstream-response body size in bytes. Unset by
    /// default — large `eth_getLogs` / `debug_traceTransaction` payloads are
    /// allowed through unbounded. Operators must set this explicitly to
    /// re-enable the cap (recommended: 8 MiB for routine traffic; higher
    /// per workload). Removing the cap removes one of the two memory-exhaustion
    /// guards on the CVM — set a value if the upstream is not fully trusted.
    #[arg(long, env = "SIDECAR_MAX_BODY_BYTES")]
    pub max_body_bytes: Option<usize>,

    /// Optional `Authorization`-style header value attached to the `/readyz`
    /// probe POST so it can pass auth gates on the upstream (e.g. shark-proxy
    /// `x-api-key`). Format: `"<HeaderName>: <HeaderValue>"`.
    #[arg(long, env = "SIDECAR_READYZ_UPSTREAM_AUTH_HEADER")]
    pub readyz_upstream_auth_header: Option<String>,

    /// Allow boot to continue when `dstack info` reports no compose hash.
    /// Default false — production deployments must bind a compose hash so
    /// `/attestation` can return a non-empty `composeHash` to verifiers.
    /// Dev/test only; set to skip the bootstrap precondition when running
    /// against a simulator that does not populate the field.
    #[arg(
        long,
        env = "SIDECAR_ALLOW_EMPTY_COMPOSE_HASH",
        default_value_t = false
    )]
    pub allow_empty_compose_hash: bool,

}
