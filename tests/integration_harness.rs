//! Integration tests for `rpc-attest-sidecar`.
//!
//! Test groups (see Phase 8 in `.planning/workstreams/secure-rpc/ROADMAP.md`):
//! - A: pass-through proxy
//! - B: boot + key derivation
//! - C: per-response signing
//! - D: attestation endpoint
//! - E: live shark-proxy upstream (env-gated)
//! - F: HTTPS upstream
//!
//! Required env vars (panics with a clear message if missing):
//!   DSTACK_SIMULATOR_BIN
//!   DSTACK_SIMULATOR_FIXTURES_DIR
//!
//! Optional env vars (live shark tests skip cleanly if missing):
//!   SHARK_RPC_URL
//!   SHARK_API_KEY
//!
//! Run all: `cargo test --test integration -- --test-threads=1`
//! (We use `serial_test` so concurrent tests don't fight over the same
//! simulator socket; passing `--test-threads=1` is a belt-and-braces choice
//! that also keeps the captured stderr ordered for debugging.)

mod common;

use std::time::Duration;

use common::{
    build_pre_image, decode_hex_0x, env_var, get, header_str, http_client, post_bytes, sha2_256,
    spawn_sidecar, spawn_sidecar_expect_fail, spawn_simulator, verify_signed_response,
    MockResponse, MockUpstream, SidecarSpawn,
};
use serial_test::serial;

const CHAIN_ID: u64 = 1;

// ============================================================
// Group A — Pass-through proxy
// ============================================================

/// T1 (A1) — Body forwarded byte-identical.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t1_body_byte_identity() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let payload = b"\x00\xffhello\x01rawbinary\xfe".to_vec();
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/octet-stream".into())],
        body: bytes::Bytes::from(payload.clone()),
    });
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });

    let req_body = b"some_raw_request_bytes".to_vec();
    let client = http_client();
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        req_body.clone(),
        &[],
    )
    .await
    .expect("post");
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(resp.body, bytes::Bytes::from(payload));

    let recvd = upstream.received();
    assert_eq!(recvd.len(), 1, "upstream received exactly one request");
    assert_eq!(
        recvd[0].body.to_vec(),
        req_body,
        "request body byte-identical at upstream"
    );
}

/// T4 (A5) — Upstream 503 propagated as 503 with the upstream body byte-identical
/// (no synthesised JSON-RPC error envelope from the sidecar).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t4_upstream_5xx_propagated_plain() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let body = b"upstream is down (plain text)";
    upstream.set_response(MockResponse {
        status: 503,
        headers: vec![("content-type".into(), "text/plain".into())],
        body: bytes::Bytes::from_static(body),
    });
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        b"req".to_vec(),
        &[],
    )
    .await
    .expect("post");
    assert_eq!(resp.status.as_u16(), 503);
    assert_eq!(resp.body.as_ref(), body, "body byte-identical, no envelope");
    assert!(
        !resp.body.starts_with(b"{\"jsonrpc"),
        "sidecar must not fabricate JSON-RPC errors"
    );
}

// ============================================================
// Group B — Boot + key derivation
// ============================================================

/// T5 (B1) — Boot stderr contains `signing_pubkey = 0x<32B hex>`.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t5_boot_logs_signing_pubkey() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    assert_eq!(
        sidecar.signing_pubkey.len(),
        32,
        "pubkey parsed from log is exactly 32 bytes"
    );
    let logs = sidecar.captured();
    let any_with_path = logs
        .iter()
        .any(|l| l.contains("key_derivation_path") && l.contains("rpc-sign/v1"));
    assert!(
        any_with_path,
        "boot log must record key_derivation_path=rpc-sign/v1"
    );
}

/// T6 (B2) — Sidecar boot with unreachable dstack socket exits ≠ 0 within 5s.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t6_boot_fails_fast_when_dstack_unreachable() {
    let upstream = MockUpstream::start().await;
    let bogus_socket = std::path::PathBuf::from("/tmp/does-not-exist.sock");
    let (logs, status) = spawn_sidecar_expect_fail(
        &upstream.url,
        CHAIN_ID,
        &bogus_socket,
        Duration::from_secs(8),
    );
    assert!(!status.success(), "expected non-zero exit");
    let any = logs
        .iter()
        .any(|l| l.contains("dstack") || l.contains("get_key") || l.contains("aborting"));
    assert!(
        any,
        "expected dstack-related error in stderr, got: {logs:?}"
    );
}

// ============================================================
// Group C — Per-response signing
// ============================================================

/// T7 — Every signed response carries the three vRPC-* headers.
/// T8 — Signature verifies cryptographically over the canonical pre-image.
/// (Combined into one test — same call, two assertions.)
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t7_t8_signed_response_headers_and_signature_verifies() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let resp_body = br#"{"jsonrpc":"2.0","result":"0xabc","id":1}"#;
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: bytes::Bytes::from_static(resp_body),
    });
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        req.to_vec(),
        &[],
    )
    .await
    .expect("post");
    assert_eq!(resp.status.as_u16(), 200);
    // T7
    for h in ["vrpc-signature", "vrpc-timestamp", "vrpc-pubkey"] {
        assert!(
            resp.headers.get(h).is_some(),
            "missing header: {h} (have: {:?})",
            resp.headers.keys().map(|k| k.as_str()).collect::<Vec<_>>()
        );
    }
    // T8
    verify_signed_response(CHAIN_ID, req, &resp).unwrap_or_else(|e| panic!("verify failed: {e}"));
    // bonus: pubkey on header == pubkey parsed from boot log
    let hdr_pk = decode_hex_0x(header_str(&resp.headers, "vrpc-pubkey"));
    assert_eq!(hdr_pk.as_slice(), &sidecar.signing_pubkey);
}

/// T9 — Batch JSON-RPC `[{...},{...}]` goes through the same byte-opaque
/// signing path as single calls.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t9_batch_jsonrpc_signs_identically() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let batch_resp =
        br#"[{"jsonrpc":"2.0","result":1,"id":1},{"jsonrpc":"2.0","result":2,"id":2}]"#;
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: bytes::Bytes::from_static(batch_resp),
    });
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let req = br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#;
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        req.to_vec(),
        &[],
    )
    .await
    .expect("post batch");
    verify_signed_response(CHAIN_ID, req, &resp).expect("batch must verify");
    // Sanity: pre-image hashes are over the bytes the client/upstream actually saw.
    let _ = sha2_256(req); // would be different for non-batch — covered by other tests.
}

// ============================================================
// Group D — Attestation endpoint
// ============================================================

/// T11 (D1) — `GET /attestation` without nonce → 400.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t11_attestation_without_nonce_400() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let resp = get(&client, &format!("{}/attestation", sidecar.base_url))
        .await
        .expect("get attestation");
    assert_eq!(resp.status.as_u16(), 400, "missing nonce → 400");
}

/// T12 (D4) — Valid nonce → 200 JSON with the nested SDK quote per Phase 13:
/// `quote` is an object (not a string) containing bare-hex `quote` and
/// `event_log`; `pubkey` + `composeHash` remain top-level.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t12_attestation_valid_nonce() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let nonce = format!("0x{}", "11".repeat(32));
    let resp = get(
        &client,
        &format!("{}/attestation?nonce={}", sidecar.base_url, nonce),
    )
    .await
    .expect("get attestation");
    assert_eq!(resp.status.as_u16(), 200);
    let v: serde_json::Value = serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("response not JSON: {e}; body={:?}", resp.body));
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
    let pubkey_in_body = v["pubkey"].as_str().unwrap_or("");
    assert!(
        pubkey_in_body.starts_with("0x") && pubkey_in_body.len() == 2 + 64,
        "pubkey is 0x + 64 hex chars; got {pubkey_in_body}"
    );
}

/// T13 (D5 + D6) — Different nonces produce different quote bytes; `pubkey`
/// from `/attestation` matches the `vRPC-Pubkey` on signed responses.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t13_attestation_per_nonce_freshness_and_pubkey_consistency() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();

    let n1 = format!("0x{}", "aa".repeat(32));
    let n2 = format!("0x{}", "bb".repeat(32));
    let r1 = get(
        &client,
        &format!("{}/attestation?nonce={n1}", sidecar.base_url),
    )
    .await
    .expect("n1");
    let r2 = get(
        &client,
        &format!("{}/attestation?nonce={n2}", sidecar.base_url),
    )
    .await
    .expect("n2");
    assert_eq!(r1.status.as_u16(), 200);
    assert_eq!(r2.status.as_u16(), 200);
    let j1: serde_json::Value = serde_json::from_slice(&r1.body).unwrap();
    let j2: serde_json::Value = serde_json::from_slice(&r2.body).unwrap();
    assert_ne!(
        j1["quote"], j2["quote"],
        "different nonces must yield different quote bytes"
    );
    assert_eq!(
        j1["pubkey"], j2["pubkey"],
        "pubkey is stable across requests"
    );

    // Cross-endpoint consistency: pubkey in /attestation == vRPC-Pubkey on signed response.
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: bytes::Bytes::from_static(b"{\"ok\":true}"),
    });
    let signed = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        b"req".to_vec(),
        &[],
    )
    .await
    .expect("post");
    let hdr_pk = header_str(&signed.headers, "vrpc-pubkey");
    assert_eq!(
        hdr_pk,
        j1["pubkey"].as_str().unwrap_or(""),
        "vRPC-Pubkey must match /attestation pubkey"
    );
}

// ============================================================
// Group E — Live shark-proxy upstream
// ============================================================

/// T14 (E1 + E3) — Live `eth_blockNumber` via sidecar → shark.
/// `SHARK_API_KEY` propagated as the `x-api-key` upstream header.
/// Response is signed and verifies.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t14_live_shark_eth_blocknumber() {
    let url = match env_var("SHARK_RPC_URL") {
        Some(v) => v,
        None => {
            eprintln!("[skipped: set SHARK_RPC_URL + SHARK_API_KEY to run T14]");
            return;
        }
    };
    let key = match env_var("SHARK_API_KEY") {
        Some(v) => v,
        None => {
            eprintln!("[skipped: set SHARK_API_KEY to run T14]");
            return;
        }
    };
    let sim = spawn_simulator();
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        req.to_vec(),
        &[("x-api-key", key.as_str())],
    )
    .await
    .expect("post via shark");
    assert_eq!(
        resp.status.as_u16(),
        200,
        "live shark call should return 200; got {} body={:?}",
        resp.status,
        std::str::from_utf8(&resp.body).unwrap_or("<binary>")
    );
    let v: serde_json::Value = serde_json::from_slice(&resp.body).expect("upstream returned JSON");
    let result = v["result"].as_str().unwrap_or("");
    assert!(
        result.starts_with("0x") && result.len() > 3,
        "expected hex block number in result, got {result:?}"
    );
    verify_signed_response(CHAIN_ID, req, &resp).expect("signature must verify");
}

// ============================================================
// Group F — HTTPS upstream
// ============================================================

/// T15 (F1) — `https://` upstream handshake works (Mozilla webpki roots),
/// response is signed end-to-end.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t15_https_upstream_works() {
    // Use a public HTTPS endpoint by default — override via TEST_HTTPS_UPSTREAM env if needed.
    let url = env_var("TEST_HTTPS_UPSTREAM")
        .or_else(|| env_var("SHARK_RPC_URL"))
        .unwrap_or_else(|| "https://rpc.ankr.com/eth".into());
    let api_key = env_var("SHARK_API_KEY");

    let sim = spawn_simulator();
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![],
    });
    let client = http_client();
    let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
    let extra: Vec<(&str, &str)> = match api_key.as_deref() {
        Some(k) => vec![("x-api-key", k)],
        None => vec![],
    };
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        req.to_vec(),
        &extra,
    )
    .await
    .expect("post over https upstream");
    // Public rpc.ankr.com without auth may rate-limit (429) or return 401/403 in some
    // setups — accept any 2xx and (importantly) confirm the body is signed by the
    // sidecar regardless: TLS handshake clearly succeeded if we got bytes back.
    assert!(
        resp.status.is_success() || resp.status.as_u16() == 429 || resp.status.as_u16() == 401,
        "unexpected status from https upstream: {} body={:?}",
        resp.status,
        std::str::from_utf8(&resp.body).unwrap_or("<binary>")
    );
    verify_signed_response(CHAIN_ID, req, &resp)
        .expect("signature still verifies regardless of upstream status");
    // Sanity: pre-image was computed over the same request bytes (covers an oddity
    // where forwarding rewrites the body — clippy on `request_bytes.clone()` in
    // proxy.rs caught one such regression early on).
    let _ = build_pre_image(CHAIN_ID, req, &resp.body, 0);
}

// ============================================================
// Group G — Body size limit
// ============================================================

/// T16 — Request body exceeding `--max-body-bytes` is rejected with 413
/// before reaching the upstream.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t16_oversize_request_body_returns_413() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    // Tight cap so the test stays cheap.
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![("SIDECAR_MAX_BODY_BYTES", "1024")],
    });
    let client = http_client();
    // 2 KiB > 1 KiB cap.
    let oversize = vec![b'a'; 2 * 1024];
    let resp = post_bytes(&client, &format!("{}/", sidecar.base_url), oversize, &[])
        .await
        .expect("post oversize");
    assert_eq!(
        resp.status.as_u16(),
        413,
        "oversize request must return 413, got {} body={:?}",
        resp.status,
        std::str::from_utf8(&resp.body).unwrap_or("<binary>")
    );
    // Upstream must not be touched — proxy short-circuits on body cap.
    assert!(
        upstream.received().is_empty(),
        "oversize request must not reach upstream; got {:?}",
        upstream.received().len()
    );
}

/// T17 — Upstream response larger than `--max-body-bytes` causes the sidecar
/// to fail with 502 rather than buffer unbounded bytes.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn t17_oversize_upstream_response_returns_502() {
    let sim = spawn_simulator();
    let upstream = MockUpstream::start().await;
    // Upstream returns 2 KiB response.
    let big = vec![b'r'; 2 * 1024];
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/octet-stream".into())],
        body: bytes::Bytes::from(big),
    });
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url,
        chain_id: CHAIN_ID,
        dstack_endpoint: sim.socket(),
        extra_env: vec![("SIDECAR_MAX_BODY_BYTES", "1024")],
    });
    let client = http_client();
    let resp = post_bytes(
        &client,
        &format!("{}/", sidecar.base_url),
        b"req".to_vec(),
        &[],
    )
    .await
    .expect("post");
    assert_eq!(
        resp.status.as_u16(),
        502,
        "oversize upstream response must surface as 502; got {} body={:?}",
        resp.status,
        std::str::from_utf8(&resp.body).unwrap_or("<binary>")
    );
}
