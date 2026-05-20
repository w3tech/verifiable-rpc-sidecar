//! Byte-compat assertion + info() smoke test for the dstack-sdk migration
//! (Phase 11, Plan 11-02).
//!
//! This file was a baseline-CAPTURE in Plan 11-01 (printed simulator output
//! with grep-able prefix tokens). Plan 11-02 upgrades it to a baseline-
//! ASSERTION: the migrated SDK-backed `DstackClient` is now exercised against
//! the simulator and its `get_key` byte output is asserted hex-equal to the
//! pre-migration baseline captured in Plan 11-01.
//!
//! Two integration tests:
//!
//! 1. `get_key_byte_compat_with_pre_migration` — RESEARCH.md Pitfall 3 / Caveat 2
//!    (HIGHEST RISK). SDK's `get_key` adds `"algorithm": "secp256k1"` to the
//!    request payload that our hand-rolled code did NOT send. If the agent uses
//!    that field in key derivation, the SDK call may return DIFFERENT bytes
//!    than the pre-migration call would — silently changing the sidecar's
//!    signing identity. This test PANICS with a migration-abort message if
//!    that happens.
//!
//! 2. `info_succeeds_against_simulator` — RESEARCH.md Pitfall 1 / Caveat 1.
//!    SDK's `InfoResponse` has REQUIRED fields (`app_cert`, `device_id`,
//!    `key_provider_info`, parsed `tcb_info`) that the simulator may omit. If
//!    `info()` returns `Err`, the sidecar fails boot via `bootstrap_tdx_identity`.
//!    This test PANICS with a clear "switch to permissive Value-based parsing"
//!    message if that happens.
//!
//! Env-gated: requires `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR`.
//! Skips cleanly with a logged message when env is unset — CI must set them
//! before merging Plan 11-02. The byte-compat check is the MERGE GATE, not
//! just a green build.
//!
//! Baseline source: Plan 11-01 was unable to capture the live simulator key
//! (env unset on the local host) and deferred to CI. The expected key hex is
//! either pinned in the `EXPECTED_BASELINE_KEY_HEX` constant below OR read
//! from the `DSTACK_BASELINE_KEY_RPC_SIGN_V1` environment variable at runtime,
//! whichever is non-empty. If both are empty, the test PANICS with a clear
//! "baseline not yet captured" message — this preserves the merge gate.

mod common;

use common::{env_var, spawn_simulator};
use dstack_sdk::dstack_client::DstackClient;

/// Expected `get_key("rpc-sign/v1", None)` byte output from the
/// PRE-migration hand-rolled `DstackClient`. Captured in Plan 11-01 against
/// the dstack simulator and pinned here as the byte-compat reference for the
/// SDK-backed implementation introduced in Plan 11-02.
///
/// Stored as the hex-encoded key string (with or without `0x` prefix). 64 hex
/// chars represents a 32-byte Ed25519 seed.
///
/// **Plan 11-01 outcome: DEFERRED TO CI** — local host had no simulator. The
/// constant is left empty; CI runs this test with
/// `DSTACK_BASELINE_KEY_RPC_SIGN_V1=0x<hex>` set in env to supply the live
/// baseline. Once the value is known from a CI run, future maintainers MAY
/// pin it here directly and drop the env-var override.
const EXPECTED_BASELINE_KEY_HEX: &str = "";

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
            "BYTE-COMPAT FAIL: baseline reference is missing. Plan 11-01 deferred capture \
             to CI; CI must export DSTACK_BASELINE_KEY_RPC_SIGN_V1=0x<64-hex-char> (the live \
             simulator key from the pre-migration commit 360df35) before running this test, \
             OR a maintainer must pin the value in EXPECTED_BASELINE_KEY_HEX. \
             See 11-RESEARCH.md Pitfall 3 and 11-01-SUMMARY.md 'Baseline Capture Output'."
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
             expected=0x{expected}, got=0x{actual_hex}. \
             See 11-RESEARCH.md Pitfall 3."
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
             Switch to permissive Value-based deserialisation in src/dstack.rs::info(). \
             Underlying error: {err:?}. \
             See 11-RESEARCH.md Pitfall 1."
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
