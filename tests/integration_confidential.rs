//! End-to-end tests for Ankr Confidential RPC (`POST /confidential`).
//!
//! Each test drives the real `rpc-attest-sidecar` binary against a fresh
//! dstack simulator and an in-process upstream. The client encrypts to the
//! key taken from `/attestation`, so these tests prove that a client which
//! only knows the attested pubkey can talk to the route.
//!
//! Covered: the test client against the Go vector, a sealed round trip,
//! a batch, the batch limit, upstream timeouts on headers and on the body,
//! the plaintext error plane and the content-free trace log.
//!
//! Required env vars (panics with a clear message if missing):
//!   DSTACK_SIMULATOR_BIN
//!   DSTACK_SIMULATOR_FIXTURES_DIR
//!
//! Run: `cargo test --test integration_confidential -- --test-threads=1`

mod common;

use std::time::{Duration, Instant};

use common::{
    bhttp_request, confidential_info, confidential_pk_r, fetch_pubkey_from_attestation, get,
    header_str, http_client, inner_response, open_confidential, post_confidential,
    seal_confidential, spawn_sidecar, spawn_simulator, verify_signed_response, ConfidentialClient,
    HttpResponse, MockResponse, MockUpstream, SidecarHandle, SidecarSpawn, SimulatorHandle,
    StallingUpstream,
};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR};
use serial_test::serial;

const CHAIN_ID: &str = "1";
const OHTTP_KEY_PROBLEM: &[u8] = br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}"#;
const ONE_CALL: &[u8] = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
const THREE_CALLS: &[u8] = br#"[{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2},{"jsonrpc":"2.0","method":"net_version","params":[],"id":3}]"#;
const JSON: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];

struct Rig {
    sidecar: SidecarHandle,
    _sim: SimulatorHandle,
    pk: [u8; 32],
    pk_r: [u8; 32],
}

impl Rig {
    async fn start(upstream_url: &str, extra_env: Vec<(&str, &str)>) -> Self {
        let sim = spawn_simulator();
        let sidecar = spawn_sidecar(SidecarSpawn {
            upstream_url,
            chain_id: CHAIN_ID,
            dstack_endpoint: sim.socket(),
            extra_env,
        });
        let pk = fetch_pubkey_from_attestation(&sidecar.base_url)
            .await
            .expect("pubkey from /attestation");
        Self {
            sidecar,
            _sim: sim,
            pk,
            pk_r: confidential_pk_r(&pk),
        }
    }

    fn url(&self) -> String {
        format!("{}/confidential", self.sidecar.base_url)
    }

    async fn call(&self, bhttp: &[u8]) -> (Vec<u8>, ConfidentialClient, HttpResponse) {
        let (outer_req, client) = seal_confidential(&self.pk_r, bhttp);
        let resp = post_confidential(&http_client(), &self.url(), outer_req.clone())
            .await
            .expect("post /confidential");
        (outer_req, client, resp)
    }
}

fn vrpc_headers(resp: &HttpResponse) -> Vec<String> {
    resp.headers
        .keys()
        .map(|k| k.as_str().to_owned())
        .filter(|k| k.starts_with("vrpc-"))
        .collect()
}

fn fields_named<'a>(fields: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Vec<&'a [u8]> {
    fields
        .iter()
        .filter(|(n, _)| n.as_slice() == name)
        .map(|(_, v)| v.as_slice())
        .collect()
}

fn assert_sealed(outer_req: &[u8], resp: &HttpResponse, status: u16, batch_size: &str) {
    assert_eq!(resp.status.as_u16(), status);
    assert_eq!(
        header_str(&resp.headers, "content-type"),
        "message/ohttp-res"
    );
    assert_eq!(header_str(&resp.headers, "vrpc-batch-size"), batch_size);
    assert!(resp.headers.get("content-encoding").is_none());
    verify_signed_response(CHAIN_ID, outer_req, resp)
        .unwrap_or_else(|e| panic!("signature over the outer bytes: {e}"));
}

fn assert_problem(client: &ConfidentialClient, resp: &HttpResponse, status: u16, body: &str) {
    let (inner_status, fields, inner_body) = inner_response(&open_confidential(client, &resp.body));
    assert_eq!(inner_status, status);
    assert_eq!(
        fields_named(&fields, b"content-type"),
        vec![b"application/problem+json".as_slice()]
    );
    assert_eq!(inner_body, body.as_bytes());
}

fn h(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().expect("hex string")).expect("hex")
}

#[test]
fn c0_test_client_matches_go_vector() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/confidential.json")).expect("vectors");
    let v = &vectors["envelopes"][0];
    let req = &v["request"];
    let fields: Vec<(Vec<u8>, Vec<u8>)> = req["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|f| {
            (
                f["name"].as_str().expect("name").as_bytes().to_vec(),
                f["value"].as_str().expect("value").as_bytes().to_vec(),
            )
        })
        .collect();
    let field_refs: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    let plaintext = bhttp_request(
        req["method"].as_str().expect("method").as_bytes(),
        req["path"].as_str().expect("path").as_bytes(),
        &field_refs,
        req["body"].as_str().expect("body").as_bytes(),
    );
    assert_eq!(plaintext, h(v, "bhttp_request"));
    assert_eq!(confidential_info(), h(v, "info"));

    let go = ConfidentialClient {
        enc: h(v, "enc"),
        secret: h(v, "export_secret").try_into().expect("32-byte secret"),
    };
    assert_eq!(
        open_confidential(&go, &h(v, "encapsulated_response")),
        h(v, "bhttp_response")
    );

    let pk_r: [u8; 32] = h(v, "pkR").try_into().expect("32-byte pkR");
    let (body, client) = seal_confidential(&pk_r, &plaintext);
    let hdr = h(v, "hdr");
    assert!(body.starts_with(&hdr));
    let (enc, ct) = body[hdr.len()..].split_at(32);
    assert_eq!(enc, client.enc.as_slice());
    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&h(v, "skR")).expect("skR");
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc).expect("enc");
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &h(v, "info"),
    )
    .expect("hpke receiver");
    assert_eq!(receiver.open(ct, b"").expect("hpke open"), plaintext);
    let mut secret = [0u8; 32];
    receiver
        .export(b"message/bhttp response", &mut secret)
        .expect("hpke export");
    assert_eq!(secret, client.secret);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c1_sealed_round_trip_uses_the_attested_key() {
    let upstream = MockUpstream::start().await;
    let node_body = br#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#;
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: bytes::Bytes::from_static(node_body),
    });
    let rig = Rig::start(&upstream.url, vec![]).await;

    let inner = bhttp_request(
        b"POST",
        b"/inner/path?q=1",
        &[
            (b"content-type", b"application/json"),
            (b"accept", b"application/json"),
            (b"x-not-forwarded", b"1"),
        ],
        ONE_CALL,
    );
    let (outer_req, client, resp) = rig.call(&inner).await;

    assert_sealed(&outer_req, &resp, 200, "1");
    assert_eq!(
        header_str(&resp.headers, "vrpc-pubkey"),
        format!("0x{}", hex::encode(rig.pk))
    );
    let (status, fields, body) = inner_response(&open_confidential(&client, &resp.body));
    assert_eq!(status, 200);
    assert_eq!(
        fields_named(&fields, b"content-type"),
        vec![b"application/json".as_slice()]
    );
    assert_eq!(body, node_body);

    let received = upstream.received();
    assert_eq!(received.len(), 1, "node called once");
    let r = &received[0];
    assert_eq!(r.method, hyper::Method::POST);
    assert_eq!(r.uri, "/inner/path?q=1");
    assert_eq!(
        r.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        r.headers.get("accept").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        r.headers.get("accept-encoding").map(String::as_str),
        Some("identity")
    );
    assert!(!r.headers.contains_key("x-not-forwarded"));
    assert_eq!(r.body.as_ref(), ONE_CALL);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c2_batch_reaches_node_as_one_batch_with_its_size() {
    let upstream = MockUpstream::start().await;
    let rig = Rig::start(&upstream.url, vec![]).await;

    let (outer_req, client, resp) = rig
        .call(&bhttp_request(b"POST", b"/", JSON, THREE_CALLS))
        .await;

    assert_sealed(&outer_req, &resp, 200, "3");
    let (status, _, _) = inner_response(&open_confidential(&client, &resp.body));
    assert_eq!(status, 200);
    let received = upstream.received();
    assert_eq!(received.len(), 1, "one node request for the whole batch");
    assert_eq!(received[0].body.as_ref(), THREE_CALLS);
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c3_batch_over_limit_is_sealed_413_without_calling_node() {
    let upstream = MockUpstream::start().await;
    let rig = Rig::start(&upstream.url, vec![("SIDECAR_MAX_BATCH_SIZE", "2")]).await;

    let (outer_req, client, resp) = rig
        .call(&bhttp_request(b"POST", b"/", JSON, THREE_CALLS))
        .await;

    assert_sealed(&outer_req, &resp, 413, "3");
    assert_problem(
        &client,
        &resp,
        413,
        r#"{"type":"urn:vrpc:error:batch-too-large","title":"Batch too large"}"#,
    );
    assert!(upstream.received().is_empty(), "node not called");
}

async fn assert_stall_is_sealed_504(prefix: &'static [u8]) {
    let upstream = StallingUpstream::start(prefix).await;
    let rig = Rig::start(
        &upstream.url,
        vec![("SIDECAR_CONFIDENTIAL_UPSTREAM_TIMEOUT_SECS", "1")],
    )
    .await;

    let started = Instant::now();
    let (outer_req, client, resp) = rig
        .call(&bhttp_request(b"POST", b"/", JSON, ONE_CALL))
        .await;
    let elapsed = started.elapsed();

    assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
    assert_eq!(upstream.conns(), 1, "node called once");
    assert_sealed(&outer_req, &resp, 504, "1");
    assert_problem(
        &client,
        &resp,
        504,
        r#"{"type":"urn:vrpc:error:upstream-timeout","title":"Upstream timeout"}"#,
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c4_stalled_headers_are_sealed_504() {
    assert_stall_is_sealed_504(b"").await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c5_stalled_body_is_sealed_504() {
    assert_stall_is_sealed_504(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"partial",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c6_plaintext_errors_carry_no_vrpc_headers() {
    let upstream = MockUpstream::start().await;
    let rig = Rig::start(&upstream.url, vec![]).await;
    let client = http_client();

    let resp = post_confidential(&client, &rig.url(), vec![0xa5; 60])
        .await
        .expect("post garbage");
    assert_eq!(resp.status.as_u16(), 400);
    assert_eq!(
        header_str(&resp.headers, "content-type"),
        "application/problem+json"
    );
    assert_eq!(resp.body.len(), 126);
    assert_eq!(resp.body.as_ref(), OHTTP_KEY_PROBLEM);
    assert!(vrpc_headers(&resp).is_empty(), "{:?}", vrpc_headers(&resp));

    let resp = get(&client, &rig.url()).await.expect("get");
    assert_eq!(resp.status.as_u16(), 405);
    assert!(vrpc_headers(&resp).is_empty(), "{:?}", vrpc_headers(&resp));

    assert!(upstream.received().is_empty(), "node not called");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn c7_trace_logs_have_one_outcome_line_per_call_and_no_content() {
    let upstream = MockUpstream::start().await;
    upstream.set_response(MockResponse {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: bytes::Bytes::from_static(b"mk-resp-body-c4a6"),
    });
    let rig = Rig::start(&upstream.url, vec![("RUST_LOG", "trace")]).await;
    let client = http_client();

    let inner = bhttp_request(
        b"POST",
        b"/mk-path-3e5b?mk-q=7a20",
        &[
            (b"content-type", b"application/mk-ct-6c19"),
            (b"accept", b"mk-accept-d047"),
        ],
        br#"{"mk":"mk-body-81f2"}"#,
    );
    let (outer_req, conf_client, resp) = rig.call(&inner).await;
    assert_sealed(&outer_req, &resp, 200, "1");
    let (_, _, body) = inner_response(&open_confidential(&conf_client, &resp.body));
    assert_eq!(body, b"mk-resp-body-c4a6");
    assert_eq!(upstream.received().len(), 1);

    let garbage = post_confidential(&client, &rig.url(), vec![0xa5; 60])
        .await
        .expect("post garbage");
    assert_eq!(garbage.status.as_u16(), 400);
    let get_resp = get(&client, &rig.url()).await.expect("get");
    assert_eq!(get_resp.status.as_u16(), 405);

    let outcome_lines = |lines: &[String]| {
        lines
            .iter()
            .filter(|l| l.contains("confidential call"))
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    while outcome_lines(&rig.sidecar.captured()) < 3 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let captured = rig.sidecar.captured();
    assert_eq!(outcome_lines(&captured), 3, "{captured:#?}");
    assert!(
        captured.iter().any(|l| l.contains("TRACE")),
        "trace level not enabled"
    );

    let markers = [
        "mk-path-3e5b".to_owned(),
        "mk-q=7a20".to_owned(),
        "mk-ct-6c19".to_owned(),
        "mk-accept-d047".to_owned(),
        "mk-body-81f2".to_owned(),
        "mk-resp-body-c4a6".to_owned(),
        hex::encode(&outer_req[..16]),
        hex::encode(&resp.body[..16]),
    ];
    for line in &captured {
        let lower = line.to_ascii_lowercase();
        for marker in &markers {
            assert!(
                !lower.contains(marker.as_str()),
                "{marker} in log line: {line}"
            );
        }
    }
}
