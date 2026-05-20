//! Pre-migration baseline capture for Phase 11 (dstack-sdk migration).
//!
//! Records the CURRENT hand-rolled `DstackClient::get_key("rpc-sign/v1", None)`
//! byte output + `info()` field shape against the dstack simulator. Plan 11-02
//! asserts the migrated SDK-backed implementation against this baseline to
//! prove byte-compatibility (RESEARCH.md Pitfall 3 — `algorithm: "secp256k1"`
//! default may shift key derivation; Pitfall 1 — SDK's strict `InfoResponse`
//! may reject simulator JSON).
//!
//! Env-gated: requires `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR`.
//! Skips cleanly with a logged message when env is unset — CI must set them
//! before merging Plan 11-02.
//!
//! All baseline lines are printed with grep-able prefix tokens
//! (`DSTACK_BASELINE_*`) so Plan 11-02 can extract them from CI logs.

mod common;

use common::{env_var, spawn_simulator};
use rpc_attest_sidecar::dstack::DstackClient;

/// Skip-with-warning gate matching the rest of the integration suite.
/// Returns `true` when env vars are present and the simulator can spawn.
fn baseline_env_ready() -> bool {
    env_var("DSTACK_SIMULATOR_BIN").is_some() && env_var("DSTACK_SIMULATOR_FIXTURES_DIR").is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn dstack_baseline_capture() {
    if !baseline_env_ready() {
        println!(
            "skipping dstack_baseline_capture — set DSTACK_SIMULATOR_BIN \
             and DSTACK_SIMULATOR_FIXTURES_DIR to capture baseline"
        );
        return;
    }

    let sim = spawn_simulator();
    let client = DstackClient::new(Some(sim.socket().to_str().expect("simulator socket utf-8")));

    // ---- get_key baseline (Pitfall 3 byte-compat source of truth) ----
    let key_resp = client
        .get_key(Some("rpc-sign/v1"), None)
        .await
        .expect("dstack get_key against simulator");
    let key_bytes = key_resp.decode_key().expect("decode_key hex");
    assert_eq!(
        key_bytes.len(),
        32,
        "Ed25519 seed must be 32 bytes (matches SigningState::from_dstack_bytes contract); \
         got {} — simulator key derivation changed",
        key_bytes.len()
    );
    println!(
        "DSTACK_BASELINE_KEY_RPC_SIGN_V1=0x{}",
        hex::encode(&key_bytes)
    );
    println!(
        "DSTACK_BASELINE_SIGNATURE_CHAIN_LEN={}",
        key_resp.signature_chain.len()
    );

    // ---- info() field-shape baseline (Pitfall 1 strict-deserialisation source of truth) ----
    let info = client.info().await.expect("dstack info against simulator");
    let raw_value = serde_json::to_value(&info).expect("re-serialise InfoResponse");

    // Per-field presence flags for the fields SDK's strict `InfoResponse` requires
    // (`app_cert`, `device_id`, `key_provider_info`, `tcb_info`, `compose_hash`).
    // Our local type uses #[serde(default)] for everything except the `extra` flatten —
    // missing fields appear as empty strings or absent keys. We surface BOTH:
    //   (a) the top-level named fields our type already breaks out;
    //   (b) the SDK-required fields the simulator emits inside `extra` (since our
    //       type doesn't have them as named fields).
    let mark = |name: &str, present: bool| {
        println!(
            "DSTACK_BASELINE_INFO_FIELD_{}={}",
            name,
            if present { "present" } else { "absent" }
        );
    };
    mark("APP_ID", !info.app_id.is_empty());
    mark("INSTANCE_ID", !info.instance_id.is_empty());
    mark("APP_NAME", !info.app_name.is_empty());
    mark("COMPOSE_HASH", !info.compose_hash.is_empty());
    mark("MR_AGGREGATED", !info.mr_aggregated.is_empty());
    mark("TCB_INFO", !info.tcb_info.is_null());

    // SDK-required fields that our local type does NOT name explicitly — they land
    // in `extra` (serde_json::Map). Plan 11-02 needs to know whether the simulator
    // emits them; if absent, the SDK's strict `InfoResponse` will fail deserialise
    // and we must fall back to Value-based parsing in the facade.
    let extra_has = |k: &str| {
        info.extra
            .get(k)
            .map(|v| match v {
                serde_json::Value::String(s) => !s.is_empty(),
                serde_json::Value::Null => false,
                _ => true,
            })
            .unwrap_or(false)
    };
    mark("APP_CERT", extra_has("app_cert"));
    mark("DEVICE_ID", extra_has("device_id"));
    mark("KEY_PROVIDER_INFO", extra_has("key_provider_info"));

    // Full raw info as pretty JSON — fenced so Plan 11-02 can scrape it from CI logs
    // and feed it through `serde_json::from_value::<SdkInfoResponse>` to test strict
    // deserialisation without re-spawning the simulator.
    let pretty = serde_json::to_string_pretty(&raw_value).expect("pretty-print info");
    println!("DSTACK_BASELINE_INFO_RAW_BEGIN");
    println!("{pretty}");
    println!("DSTACK_BASELINE_INFO_RAW_END");
}
