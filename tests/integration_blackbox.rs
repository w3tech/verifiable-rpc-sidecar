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
    acquire_blackbox_sidecar, decode_hex_0x, env_var, get, gunzip, header_str, http_client,
    post_bytes, verify_signed_response,
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
    // app_compose: raw verbatim preimage of composeHash, byte-identical to what
    // /info reports. A locally-spawned sidecar always exposes it; an external
    // sidecar that predates the field is skipped rather than hard-failed.
    match v["app_compose"].as_str() {
        Some(app_compose) => {
            let info_resp = get(&client, &format!("{}/info", s.base_url))
                .await
                .expect("info");
            let info: serde_json::Value = serde_json::from_slice(&info_resp.body)
                .unwrap_or_else(|e| panic!("/info not JSON: {e}"));
            assert_eq!(
                app_compose,
                info["tcb_info"]["app_compose"].as_str().unwrap_or_default(),
                "attestation.app_compose must equal /info tcb_info.app_compose verbatim"
            );
            // composeHash, when bound (the simulator may leave it empty under
            // --allow-empty-compose-hash), MUST be sha256(utf8(app_compose)) —
            // raw bytes, no canonicalization.
            let compose_hash = v["composeHash"].as_str().unwrap_or_default();
            if !compose_hash.is_empty() {
                use sha2::{Digest, Sha256};
                let recomputed = hex::encode(Sha256::digest(app_compose.as_bytes()));
                assert_eq!(
                    recomputed, compose_hash,
                    "sha256(app_compose) must equal composeHash (raw bytes, no canonicalization)"
                );
            }
        }
        None => assert!(
            !acq.has_mock_upstream(),
            "locally-spawned sidecar must expose app_compose on /attestation"
        ),
    }
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

/// BB7 — ENC-01: the upstream node always receives `Accept-Encoding: identity`,
/// regardless of what the client requested. Local-mode only (needs mock-upstream
/// introspection); external mode returns early.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb7_upstream_always_gets_identity() {
    let acq = acquire_blackbox_sidecar().await;
    if !acq.has_mock_upstream() {
        return; // external sidecar: no mock to introspect
    }
    let s = acq.as_ref();
    let client = http_client();
    // Client asks for gzip — sidecar must replace it with identity upstream.
    let resp = post_bytes(
        &client,
        &format!("{}/", s.base_url),
        default_test_body(),
        &[("accept-encoding", "gzip, br")],
    )
    .await
    .expect("post");
    assert!(resp.status.is_success(), "method POST should succeed");

    let received = acq.mock_upstream().expect("mock upstream").received();
    assert!(!received.is_empty(), "mock upstream recorded no request");
    let last = received.last().unwrap();
    let ae = last
        .headers
        .get("accept-encoding")
        .map(String::as_str)
        .unwrap_or("");
    assert_eq!(
        ae, "identity",
        "upstream must receive accept-encoding: identity, got `{ae}`"
    );
}

/// BB8 — ENC-04 (gzip): a client requesting gzip gets `Content-Encoding: gzip`,
/// and the signature verifies over the gzip-DECODED (plaintext) body.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb8_gzip_client_verifies_after_decode() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let body = default_test_body();
    let mut resp = post_bytes(
        &client,
        &format!("{}/", s.base_url),
        body.clone(),
        &[("accept-encoding", "gzip")],
    )
    .await
    .expect("post");
    assert_eq!(
        header_str(&resp.headers, "content-encoding"),
        "gzip",
        "gzip client must receive content-encoding: gzip"
    );
    // Decode the wire body, then verify against the plaintext.
    let decoded = gunzip(&resp.body);
    resp.body = bytes::Bytes::from(decoded);
    verify_signed_response(s.chain_id, &body, &resp)
        .unwrap_or_else(|e| panic!("verify over decoded body failed: {e}"));
}

/// BB9 — ENC-04 (identity): a client requesting identity gets an uncompressed
/// body and the signature verifies over it as-is.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb9_identity_client_verifies() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let body = default_test_body();
    let resp = post_bytes(
        &client,
        &format!("{}/", s.base_url),
        body.clone(),
        &[("accept-encoding", "identity")],
    )
    .await
    .expect("post");
    assert_ne!(
        header_str(&resp.headers, "content-encoding"),
        "gzip",
        "identity client must not receive gzip"
    );
    verify_signed_response(s.chain_id, &body, &resp)
        .unwrap_or_else(|e| panic!("verify over identity body failed: {e}"));
}

/// BB10 — ENC-02 regression: the signature is over the content-DECODED body.
/// For a gzip response, verifying the RAW (still-compressed) body must FAIL,
/// while verifying the gunzip-decoded body must PASS. This proves plaintext is
/// signed, not the wire bytes.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn bb10_signature_is_over_decoded_body() {
    let acq = acquire_blackbox_sidecar().await;
    let s = acq.as_ref();
    let client = http_client();
    let body = default_test_body();
    let resp = post_bytes(
        &client,
        &format!("{}/", s.base_url),
        body.clone(),
        &[("accept-encoding", "gzip")],
    )
    .await
    .expect("post");
    assert_eq!(
        header_str(&resp.headers, "content-encoding"),
        "gzip",
        "expected gzip response"
    );
    // Raw compressed body must NOT verify.
    assert!(
        verify_signed_response(s.chain_id, &body, &resp).is_err(),
        "signature must not verify over raw compressed bytes"
    );
    // Decoded body must verify.
    let mut decoded_resp = resp;
    decoded_resp.body = bytes::Bytes::from(gunzip(&decoded_resp.body));
    verify_signed_response(s.chain_id, &body, &decoded_resp)
        .unwrap_or_else(|e| panic!("signature must verify over decoded body: {e}"));
}
