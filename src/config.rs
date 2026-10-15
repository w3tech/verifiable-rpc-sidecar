// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

use std::net::SocketAddr;

use clap::Parser;

use crate::signing::validate_chain_id;

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Verifiable RPC sidecar — see README.md")]
pub struct Config {
    /// Address the sidecar listens on. Plain HTTP only — no TLS listener.
    #[arg(long, env = "SIDECAR_LISTEN_ADDR", default_value = "0.0.0.0:8545")]
    pub listen_addr: SocketAddr,

    /// Upstream EVM JSON-RPC URL. Plain HTTP — co-located inside the CVM.
    #[arg(long, env = "SIDECAR_UPSTREAM_URL")]
    pub upstream_url: String,

    /// Chain id bound into the signing pre-image as `sha256(utf8(chain_id))`.
    /// An opaque string — never parsed numerically: `42161`, `0x89`, TON's
    /// `-239`, Stellar's network id (64-char hex) are all just strings. Must be
    /// non-empty, at most 64 bytes, printable ASCII, no whitespace.
    #[arg(long, env = "SIDECAR_CHAIN_ID", value_parser = validate_chain_id)]
    pub chain_id: String,

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

    /// Maximum request body in bytes for Ankr Confidential RPC
    /// (`POST /confidential`); independent of `--max-body-bytes`.
    #[arg(
        long,
        env = "SIDECAR_CONFIDENTIAL_MAX_BODY_BYTES",
        default_value_t = 8 * 1024 * 1024
    )]
    pub confidential_max_body_bytes: usize,

    /// Maximum node response body in bytes for Ankr Confidential RPC; a larger
    /// body is an encrypted 502. Independent of `--max-body-bytes`.
    #[arg(
        long,
        env = "SIDECAR_CONFIDENTIAL_MAX_RESPONSE_BYTES",
        default_value_t = 128 * 1024 * 1024
    )]
    pub confidential_max_response_bytes: usize,

    /// Maximum number of calls in one Ankr Confidential RPC batch
    /// (`POST /confidential`), 1 to 1000.
    #[arg(
        long,
        env = "SIDECAR_MAX_BATCH_SIZE",
        default_value_t = 1000,
        value_parser = clap::value_parser!(u16).range(1..=1000)
    )]
    pub max_batch_size: u16,

    /// Timeout in seconds for the node call of Ankr Confidential RPC (connect,
    /// response headers and body); keep it below the timeout of the caller in
    /// front of the sidecar so the client receives a signed 504.
    #[arg(
        long,
        env = "SIDECAR_CONFIDENTIAL_UPSTREAM_TIMEOUT_SECS",
        default_value_t = 25,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub confidential_upstream_timeout_secs: u64,

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

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    const ARGS: [&str; 7] = [
        "rpc-attest-sidecar",
        "--upstream-url",
        "http://127.0.0.1:1",
        "--chain-id",
        "1",
        "--max-body-bytes",
        "16",
    ];

    #[test]
    fn confidential_cap_defaults_to_8_mib_independent_of_max_body_bytes() {
        let config = Config::try_parse_from(ARGS).expect("config");
        assert_eq!(config.confidential_max_body_bytes, 8_388_608);
        assert_eq!(config.max_body_bytes, Some(16));

        let config = Config::try_parse_from(
            ARGS.into_iter()
                .chain(["--confidential-max-body-bytes", "100"]),
        )
        .expect("config");
        assert_eq!(config.confidential_max_body_bytes, 100);
    }

    #[test]
    fn max_batch_size_defaults_to_1000_within_1_to_1000() {
        let parse = |value: &str| {
            let flag = format!("--max-batch-size={value}");
            Config::try_parse_from(ARGS.into_iter().chain([flag.as_str()]))
        };
        assert_eq!(
            Config::try_parse_from(ARGS).expect("config").max_batch_size,
            1000
        );
        for value in [1, 1000] {
            let config = parse(&value.to_string()).expect("config");
            assert_eq!(config.max_batch_size, value);
        }
        for value in ["0", "1001", "5000", "-1", "x"] {
            assert!(parse(value).is_err(), "{value}");
        }
        let command = Config::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "max_batch_size")
            .expect("max_batch_size argument");
        assert_eq!(
            arg.get_env(),
            Some(std::ffi::OsStr::new("SIDECAR_MAX_BATCH_SIZE"))
        );
    }

    #[test]
    fn confidential_upstream_timeout_defaults_to_25_s() {
        let parse = |value: &str| {
            let flag = format!("--confidential-upstream-timeout-secs={value}");
            Config::try_parse_from(ARGS.into_iter().chain([flag.as_str()]))
        };
        assert_eq!(
            Config::try_parse_from(ARGS)
                .expect("config")
                .confidential_upstream_timeout_secs,
            25
        );
        assert!(parse("0").is_err());
        assert_eq!(
            parse("1")
                .expect("config")
                .confidential_upstream_timeout_secs,
            1
        );
        let command = Config::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "confidential_upstream_timeout_secs")
            .expect("confidential_upstream_timeout_secs argument");
        assert_eq!(
            arg.get_env(),
            Some(std::ffi::OsStr::new(
                "SIDECAR_CONFIDENTIAL_UPSTREAM_TIMEOUT_SECS"
            ))
        );
    }

    #[test]
    fn confidential_response_cap_defaults_to_128_mib_independent_of_max_body_bytes() {
        let config = Config::try_parse_from(ARGS).expect("config");
        assert_eq!(config.confidential_max_response_bytes, 134_217_728);
        assert_eq!(config.max_body_bytes, Some(16));

        let config = Config::try_parse_from(
            ARGS.into_iter()
                .chain(["--confidential-max-response-bytes", "13"]),
        )
        .expect("config");
        assert_eq!(config.confidential_max_response_bytes, 13);

        let command = Config::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "confidential_max_response_bytes")
            .expect("confidential_max_response_bytes argument");
        assert_eq!(
            arg.get_env(),
            Some(std::ffi::OsStr::new(
                "SIDECAR_CONFIDENTIAL_MAX_RESPONSE_BYTES"
            ))
        );
    }
}
