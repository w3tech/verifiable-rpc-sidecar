//! Black-box integration tests — work against ANY running sidecar.
//!
//! Two modes, picked at runtime by `acquire_blackbox_sidecar`:
//!
//! - **External:** `SIDECAR_URL` + `SIDECAR_CHAIN_ID` env vars point at an
//!   already-deployed sidecar (e.g. one running in a real TDX CVM or on a
//!   shared dev box). The pubkey is bootstrapped from `/attestation`.
//! - **Local:** if the env vars are absent, spawn a fresh sidecar + simulator + mock upstream, same as the harness tests. Requires `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR`.
//!
//! Same test functions run in both modes. The assertions don't depend on
//! mock-upstream introspection — only on what a real client can observe.
//!
//! Optional env (used by some tests against external sidecars):
//!   SIDECAR_TEST_BODY        — raw body to POST `/` (default: eth_blockNumber JSON-RPC)
//!   SIDECAR_AUTH_HEADER_KEY  — header name added to each method POST (e.g. `x-api-key`)
//!   SIDECAR_AUTH_HEADER_VAL  — header value
//!
//! Run: `cargo test --test integration_blackbox -- --test-threads=1`

mod common;

use common::{
    acquire_blackbox_sidecar, decode_hex_0x, env_var, get, header_str, http_client, post_bytes,
    verify_signed_response,
};
use serial_test::serial;

fn default_test_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#.to_vec()
}

fn auth_header_pair() -> Option<(String, String)> {
    let key = env_var("SIDECAR_AUTH_HEADER_KEY")?;
    let val = env_var("SIDECAR_AUTH_HEADER_VAL").or_else(|| env_var("SHARK_API_KEY"))?;
    Some((key, val))
}

/// BB2 — `GET /attestation` without nonce → 400.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb2_attestation_without_nonce_400() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let resp = get(&client, &format!("{}/attestation", s.base_url))
        .await
        .expect("attestation");
    assert_eq!(resp.status.as_u16(), 400);
}

/// BB3 — `GET /attestation?nonce=<32B hex>` returns the nested SDK quote per
/// Phase 13: `quote` is an object (not a string) containing bare-hex `quote`
/// and `event_log`; `pubkey` + `composeHash` remain top-level. The route is
/// never signed.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb3_attestation_valid_nonce() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let nonce = format!("0x{}", "11".repeat(32));
    let resp = get(
        &client,
        &format!("{}/attestation?nonce={nonce}", s.base_url),
    )
    .await
    .expect("attestation");
    assert_eq!(resp.status.as_u16(), 200);
    let v: serde_json::Value =
        serde_json::from_slice(&resp.body).unwrap_or_else(|e| panic!("/attestation not JSON: {e}"));
    // Nested SDK quote object (Phase 13).
    assert!(
        v["quote"].is_object(),
        "attestation.quote must be a JSON object (nested SDK quote); got {v}"
    );
    let q = v["quote"]["quote"].as_str().unwrap_or("");
    assert!(!q.is_empty(), "attestation.quote.quote must be non-empty");
    assert!(
        !q.starts_with("0x"),
        "attestation.quote.quote must be bare hex (no 0x prefix); got {q}"
    );
    assert!(
        v["quote"]["event_log"].is_string(),
        "attestation.quote.event_log must be a string; got {v}"
    );
    assert!(
        v["composeHash"].is_string(),
        "attestation.composeHash must be a string; got {v}"
    );
    let pk = v["pubkey"].as_str().unwrap_or("");
    assert!(
        pk.starts_with("0x") && pk.len() == 2 + 64,
        "pubkey must be 0x + 64 hex; got {pk}"
    );
    // Attestation route itself is never signed.
    for h in ["vrpc-signature", "vrpc-timestamp", "vrpc-pubkey"] {
        assert!(
            resp.headers.get(h).is_none(),
            "/attestation must not emit {h}"
        );
    }
}

/// BB4 — Two different nonces → two different `quote` bytes (no caching).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb4_attestation_per_nonce_freshness() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let n1 = format!("0x{}", "aa".repeat(32));
    let n2 = format!("0x{}", "bb".repeat(32));
    let r1 = get(&client, &format!("{}/attestation?nonce={n1}", s.base_url))
        .await
        .expect("n1");
    let r2 = get(&client, &format!("{}/attestation?nonce={n2}", s.base_url))
        .await
        .expect("n2");
    let j1: serde_json::Value = serde_json::from_slice(&r1.body).unwrap();
    let j2: serde_json::Value = serde_json::from_slice(&r2.body).unwrap();
    assert_ne!(
        j1["quote"], j2["quote"],
        "different nonces → different quotes"
    );
    assert_eq!(j1["pubkey"], j2["pubkey"], "pubkey stable across requests");
}

/// BB5 — Method response is signed end-to-end and the signature verifies
/// over the canonical pre-image with the bootstrapped pubkey.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb5_method_response_signed_and_verifies() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let body = env_var("SIDECAR_TEST_BODY")
        .map(|x| x.into_bytes())
        .unwrap_or_else(default_test_body);
    let extra: Vec<(String, String)> = auth_header_pair().into_iter().collect();
    let headers: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let resp = post_bytes(&client, &format!("{}/", s.base_url), body.clone(), &headers)
        .await
        .expect("post");
    for h in ["vrpc-signature", "vrpc-timestamp", "vrpc-pubkey"] {
        assert!(
            resp.headers.get(h).is_some(),
            "missing header {h} on method response"
        );
    }
    // The bootstrapped pubkey (from /attestation) must equal the pubkey on
    // the signed response — proves cross-endpoint consistency.
    let hdr_pk = decode_hex_0x(header_str(&resp.headers, "vrpc-pubkey"));
    assert_eq!(
        hdr_pk.as_slice(),
        &s.signing_pubkey,
        "vRPC-Pubkey must match /attestation pubkey"
    );
    verify_signed_response(s.chain_id, &body, &resp)
        .unwrap_or_else(|e| panic!("verify failed: {e}"));
}

/// BB6 — Signature actually binds the body bytes: flipping one byte of the
/// response (locally, in the test) must break verification.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb6_signature_binds_response_body() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let body = env_var("SIDECAR_TEST_BODY")
        .map(|x| x.into_bytes())
        .unwrap_or_else(default_test_body);
    let extra: Vec<(String, String)> = auth_header_pair().into_iter().collect();
    let headers: Vec<(&str, &str)> = extra
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut resp = post_bytes(&client, &format!("{}/", s.base_url), body.clone(), &headers)
        .await
        .expect("post");
    verify_signed_response(s.chain_id, &body, &resp).expect("genuine resp must verify");
    // Tamper the in-memory body and re-verify — must fail.
    let mut tampered = resp.body.to_vec();
    if tampered.is_empty() {
        tampered.push(0x00);
    } else {
        tampered[0] ^= 0x01;
    }
    resp.body = bytes::Bytes::from(tampered);
    assert!(
        verify_signed_response(s.chain_id, &body, &resp).is_err(),
        "verify must fail after one-byte body flip"
    );
}

/// BB-INFO — `GET /info` returns the full `dstack.info()` response. Confirms
/// the testing endpoint exposes `tcb_info.app_compose` (the canonical JSON
/// the `composeHash` is computed over) as a nested object alongside the
/// top-level `compose_hash`. Unsigned route — no `vRPC-*` headers.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb_info_endpoint_returns_dstack_info() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let resp = get(&client, &format!("{}/info", s.base_url))
        .await
        .expect("info");
    assert_eq!(resp.status.as_u16(), 200);

    let v: serde_json::Value =
        serde_json::from_slice(&resp.body).unwrap_or_else(|e| panic!("/info not JSON: {e}"));

    assert!(
        v["app_id"].is_string(),
        "info.app_id must be string; got {v}"
    );
    assert!(
        v["compose_hash"].is_string(),
        "info.compose_hash must be string; got {v}"
    );
    assert!(
        v["tcb_info"].is_object(),
        "info.tcb_info must be a nested JSON object (not stringified); got {v}"
    );
    assert!(
        v["tcb_info"]["app_compose"].is_string(),
        "info.tcb_info.app_compose must be string; got {v}"
    );
    assert!(
        v["tcb_info"]["rtmr3"].is_string(),
        "info.tcb_info.rtmr3 must be string; got {v}"
    );

    // Unsigned route — sidecar must not emit any vRPC-* headers.
    for h in ["vrpc-signature", "vrpc-timestamp", "vrpc-pubkey"] {
        assert!(resp.headers.get(h).is_none(), "/info must not emit {h}");
    }
}
