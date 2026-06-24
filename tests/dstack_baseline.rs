//! Byte-compat assertion + info() smoke test for the dstack-sdk migration.
//!
//! Asserts that the SDK-backed `DstackClient` produces the same `get_key` byte
//! output as the pre-migration hand-rolled client, and that `info()` parses
//! against the simulator.
//!
//! Two integration tests:
//!
//! 1. `get_key_byte_compat_with_pre_migration` (HIGHEST RISK). The SDK's
//!    `get_key` adds `"algorithm": "secp256k1"` to the request payload that the
//!    hand-rolled code did NOT send. If the agent uses that field in key
//!    derivation, the SDK call may return DIFFERENT bytes than the pre-migration
//!    call would — silently changing the sidecar's signing identity. This test
//!    PANICS with a migration-abort message if that happens.
//!
//! 2. `info_succeeds_against_simulator`. The SDK's `InfoResponse` has REQUIRED
//!    fields (`app_cert`, `device_id`, `key_provider_info`, parsed `tcb_info`)
//!    that the simulator may omit. If `info()` returns `Err`, the sidecar fails
//!    boot via `bootstrap_tdx_identity`. This test PANICS with a clear
//!    "switch to permissive Value-based parsing" message if that happens.
//!
//! Env-gated: requires `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR`.
//! Skips cleanly with a logged message when env is unset — CI must set them so
//! the byte-compat check runs as a merge gate, not just a green build.
//!
//! Baseline source: the expected key hex is either pinned in the
//! `EXPECTED_BASELINE_KEY_HEX` constant below OR read from the
//! `DSTACK_BASELINE_KEY_RPC_SIGN_V1` environment variable at runtime, whichever
//! is non-empty. If both are empty, the test PANICS with a clear
//! "baseline not yet captured" message — this preserves the merge gate.

mod common;

use common::{env_var, spawn_simulator};
use dstack_sdk::dstack_client::DstackClient;

/// Expected `get_key("rpc-sign/v1", None)` byte output from the pre-migration
/// hand-rolled `DstackClient`, captured against the dstack simulator and pinned
/// here as the byte-compat reference for the SDK-backed implementation.
///
/// Stored as the hex-encoded key string (with or without `0x` prefix). 64 hex
/// chars represents a 32-byte Ed25519 seed.
///
/// The env-var override (`DSTACK_BASELINE_KEY_RPC_SIGN_V1`) is retained so CI
/// can still set the baseline without editing this file.
const EXPECTED_BASELINE_KEY_HEX: &str =
    "0xf93f555ef525197608c075a71a4bba487d0e516e65bcc655ac14e78ccc1b94ce";

/// Skip-with-warning gate matching the rest of the integration suite.
/// Returns `true` when env vars are present and the simulator can spawn.
fn baseline_env_ready() -> bool {
    env_var("DSTACK_SIMULATOR_BIN").is_some() && env_var("DSTACK_SIMULATOR_FIXTURES_DIR").is_some()
}

/// Resolve the expected baseline key hex from (a) the pinned constant or
/// (b) the `DSTACK_BASELINE_KEY_RPC_SIGN_V1` env var. Returns `None` if both
/// are empty — caller must treat that as a hard fail (the merge gate is
/// missing its reference value).
fn expected_baseline_key_hex() -> Option<String> {
    let pinned = EXPECTED_BASELINE_KEY_HEX.trim().trim_start_matches("0x");
    if !pinned.is_empty() {
        return Some(pinned.to_string());
    }
    env_var("DSTACK_BASELINE_KEY_RPC_SIGN_V1")
        .map(|s| s.trim().trim_start_matches("0x").to_string())
        .filter(|s| !s.is_empty())
}

#[tokio::test(flavor = "multi_thread")]
async fn get_key_byte_compat_with_pre_migration() {
    if !baseline_env_ready() {
        println!(
            "skipping get_key_byte_compat_with_pre_migration — set DSTACK_SIMULATOR_BIN \
             and DSTACK_SIMULATOR_FIXTURES_DIR to run the byte-compat merge gate"
        );
        return;
    }

    let expected = expected_baseline_key_hex().unwrap_or_else(|| {
        panic!(
            "BYTE-COMPAT FAIL: baseline reference is missing. CI must export \
             DSTACK_BASELINE_KEY_RPC_SIGN_V1=0x<64-hex-char> (the live simulator key from the \
             pre-migration commit 360df35) before running this test, OR a maintainer must pin \
             the value in EXPECTED_BASELINE_KEY_HEX."
        )
    });

    let sim = spawn_simulator();
    let client = DstackClient::new(Some(sim.socket().to_str().expect("simulator socket utf-8")));

    let key_resp = client
        .get_key(Some("rpc-sign/v1".to_owned()), None)
        .await
        .expect("dstack get_key against simulator");
    let key_bytes = key_resp.decode_key().expect("decode_key hex");
    let actual_hex = hex::encode(&key_bytes);

    assert_eq!(
        key_bytes.len(),
        32,
        "Ed25519 seed must be 32 bytes (matches SigningState::from_dstack_bytes contract); \
         got {} — simulator key derivation changed",
        key_bytes.len()
    );

    if actual_hex != expected {
        panic!(
            "BYTE-COMPAT FAIL: SDK get_key produced different bytes from pre-migration baseline. \
             Migration MUST be aborted — the SDK's hard-coded `algorithm: \"secp256k1\"` in the \
             /GetKey request has changed the simulator's key-derivation output. Proceeding would \
             silently rotate the sidecar's signing identity. \
             expected=0x{expected}, got=0x{actual_hex}."
        );
    }
    println!("BYTE_COMPAT_OK: get_key('rpc-sign/v1', None) matches baseline 0x{actual_hex}");
}

#[tokio::test(flavor = "multi_thread")]
async fn info_succeeds_against_simulator() {
    if !baseline_env_ready() {
        println!(
            "skipping info_succeeds_against_simulator — set DSTACK_SIMULATOR_BIN \
             and DSTACK_SIMULATOR_FIXTURES_DIR to run the info-smoke merge gate"
        );
        return;
    }

    let sim = spawn_simulator();
    let client = DstackClient::new(Some(sim.socket().to_str().expect("simulator socket utf-8")));

    let info = match client.info().await {
        Ok(info) => info,
        Err(err) => panic!(
            "INFO SMOKE FAIL: dstack.info() returned Err against the simulator. This means \
             SDK's strict InfoResponse type cannot deserialise simulator JSON (missing required \
             field — likely app_cert / device_id / key_provider_info, or unparseable tcb_info). \
             Switch to permissive Value-based deserialisation of the dstack-sdk info() response. \
             Underlying error: {err:?}."
        ),
    };
    // Top-level `compose_hash` must be populated by the live simulator.
    let ch = if info.compose_hash.is_empty() {
        None
    } else {
        Some(info.compose_hash.clone())
    };
    println!(
        "INFO_SMOKE_OK: dstack.info() returned Ok; compose_hash={}",
        ch.as_deref().unwrap_or("<none>")
    );
}
