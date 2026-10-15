// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead as _, KeyInit};
use axum::http::HeaderMap;
use ed25519_dalek::{Verifier, VerifyingKey};
use hkdf::Hkdf;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde_json::Value;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::signing::{build_pre_image, sha256};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../tests/vectors/confidential.json")).expect("vectors")
}

fn env0() -> Value {
    vectors()["envelopes"][0].clone()
}

fn vector_hex(v: &Value, key: &str) -> Vec<u8> {
    h(v[key].as_str().expect("hex string"))
}

struct OsRng;

impl hpke::rand_core::TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        hpke::rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        hpke::rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        getrandom::fill(dest).expect("os rng");
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for OsRng {}

fn varint(v: usize, out: &mut Vec<u8>) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else {
        assert!(v < 1 << 30);
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    }
}

fn vec_(bytes: &[u8], out: &mut Vec<u8>) {
    varint(bytes.len(), out);
    out.extend_from_slice(bytes);
}

fn field_section(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut section = Vec::new();
    for (name, value) in fields {
        vec_(name, &mut section);
        vec_(value, &mut section);
    }
    section
}

#[allow(clippy::too_many_arguments)]
fn encode_request(
    framing: &[u8],
    method: &[u8],
    scheme: &[u8],
    authority: &[u8],
    path: &[u8],
    fields: &[(&[u8], &[u8])],
    body: &[u8],
    trailer: &[(&[u8], &[u8])],
) -> Vec<u8> {
    let mut out = framing.to_vec();
    for control in [method, scheme, authority, path] {
        vec_(control, &mut out);
    }
    vec_(&field_section(fields), &mut out);
    vec_(body, &mut out);
    vec_(&field_section(trailer), &mut out);
    out
}

fn bhttp_request(method: &[u8], path: &[u8], fields: &[(&[u8], &[u8])], body: &[u8]) -> Vec<u8> {
    encode_request(
        &[0x00],
        method,
        b"https",
        b"localhost",
        path,
        fields,
        body,
        &[],
    )
}

struct ClientCtx {
    enc: Vec<u8>,
    secret: [u8; 32],
}

fn seal(pk_r: &[u8], plaintext: &[u8]) -> (Vec<u8>, ClientCtx) {
    let v = env0();
    let pk = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(pk_r).expect("pkR");
    let (enc, mut ctx) = hpke::setup_sender_with_rng::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &pk,
        &vector_hex(&v, "info"),
        &mut OsRng,
    )
    .expect("hpke sender");
    let ct = ctx.seal(plaintext, b"").expect("hpke seal");
    let mut secret = [0u8; 32];
    ctx.export(b"message/bhttp response", &mut secret)
        .expect("hpke export");
    let enc = enc.to_bytes().to_vec();
    let mut body = vector_hex(&v, "hdr");
    body.extend_from_slice(&enc);
    body.extend_from_slice(&ct);
    (body, ClientCtx { enc, secret })
}

fn open_response(ctx: &ClientCtx, body: &[u8]) -> Vec<u8> {
    assert!(body.len() >= 32, "response shorter than its nonce");
    let (nonce, ct) = body.split_at(32);
    let mut salt = ctx.enc.clone();
    salt.extend_from_slice(nonce);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ctx.secret);
    let mut key = [0u8; 32];
    hk.expand(b"key", &mut key).expect("hkdf key");
    let mut aead_nonce = [0u8; 12];
    hk.expand(b"nonce", &mut aead_nonce).expect("hkdf nonce");
    aes_gcm::Aes256Gcm::new_from_slice(&key)
        .expect("aes key")
        .decrypt(&aead_nonce.into(), ct)
        .expect("open response")
}

fn inner_response(ctx: &ClientCtx, body: &[u8]) -> bhttp::Message {
    let plaintext = open_response(ctx, body);
    bhttp::Message::read_bhttp(&mut Cursor::new(&plaintext[..])).expect("inner bhttp response")
}

fn inner_fields(msg: &bhttp::Message) -> Vec<(Vec<u8>, Vec<u8>)> {
    msg.header()
        .iter()
        .map(|f| (f.name().to_vec(), f.value().to_vec()))
        .collect()
}

#[test]
fn test_client_is_pinned_to_go_vector() {
    let v = env0();
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
    assert_eq!(plaintext, vector_hex(&v, "bhttp_request"));

    let hdr = vector_hex(&v, "hdr");
    let (body, client) = seal(&vector_hex(&v, "pkR"), &plaintext);
    assert!(body.starts_with(&hdr));
    let (enc, ct) = body[hdr.len()..].split_at(32);
    let sk = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&vector_hex(&v, "skR"))
        .expect("skR");
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc).expect("enc");
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &vector_hex(&v, "info"),
    )
    .expect("hpke receiver");
    assert_eq!(receiver.open(ct, b"").expect("hpke open"), plaintext);
    let mut secret = [0u8; 32];
    receiver
        .export(b"message/bhttp response", &mut secret)
        .expect("hpke export");
    assert_eq!(secret, client.secret);

    let go = ClientCtx {
        enc: vector_hex(&v, "enc"),
        secret: vector_hex(&v, "export_secret")
            .try_into()
            .expect("32-byte secret"),
    };
    assert_eq!(
        open_response(&go, &vector_hex(&v, "encapsulated_response")),
        vector_hex(&v, "bhttp_response")
    );

    let resp = InnerResponse {
        status: 200,
        content_type: vec![HeaderValue::from_static("application/json")],
        body: Bytes::from(
            v["response"]["body"]
                .as_str()
                .expect("response body")
                .to_owned(),
        ),
    };
    assert_eq!(
        encode_response(&resp).expect("encode"),
        vector_hex(&v, "bhttp_response")
    );
}

#[derive(Default)]
struct Mock {
    conns: AtomicUsize,
    received: Mutex<Vec<Vec<u8>>>,
    replied_at_ms: Mutex<Vec<u64>>,
}

impl Mock {
    fn conns(&self) -> usize {
        self.conns.load(Ordering::SeqCst)
    }

    fn request(&self, i: usize) -> UpstreamRequest {
        UpstreamRequest::parse(&self.received.lock().expect("mock lock")[i])
    }
}

fn request_complete(acc: &[u8]) -> bool {
    let Some(end) = acc.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    parsed.parse(acc).expect("parse mock request");
    let content_length = parsed
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| {
            std::str::from_utf8(h.value)
                .expect("ascii content-length")
                .parse::<usize>()
                .expect("numeric content-length")
        })
        .unwrap_or(0);
    acc.len() >= end + 4 + content_length
}

async fn mock(reply: &'static [u8]) -> (String, Arc<Mock>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let state = Arc::new(Mock::default());
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            shared.conns.fetch_add(1, Ordering::SeqCst);
            let mut acc = Vec::new();
            let mut buf = vec![0u8; 65536];
            while !request_complete(&acc) {
                let n = stream.read(&mut buf).await.expect("read mock");
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
            }
            shared.received.lock().expect("mock lock").push(acc);
            shared
                .replied_at_ms
                .lock()
                .expect("mock lock")
                .push(crate::signing::now_ms().expect("clock"));
            let _ = stream.write_all(reply).await;
            let _ = stream.shutdown().await;
        }
    });
    (url, state)
}

struct UpstreamRequest {
    line: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl UpstreamRequest {
    fn parse(raw: &[u8]) -> Self {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("request line");
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Request::new(&mut headers);
        let head_len = match parsed.parse(raw).expect("parse upstream request") {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => panic!("partial upstream request"),
        };
        Self {
            line: String::from_utf8(raw[..line_end].to_vec()).expect("utf-8 request line"),
            headers: parsed
                .headers
                .iter()
                .map(|h| (h.name.to_ascii_lowercase(), h.value.to_vec()))
                .collect(),
            body: raw[head_len..].to_vec(),
        }
    }

    fn names(&self) -> Vec<&str> {
        self.headers.iter().map(|(n, _)| n.as_str()).collect()
    }

    fn values(&self) -> Vec<&[u8]> {
        self.headers.iter().map(|(_, v)| v.as_slice()).collect()
    }
}

const OK_BODY: &[u8] = b"{\"result\":1}\n";
const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nServer: node\r\nX-Leak: 1\r\nContent-Length: 13\r\n\r\n{\"result\":1}\n";

fn signer() -> SigningState {
    let seed: [u8; 32] = vector_hex(&vectors()["key_conversion"][0], "seed")
        .try_into()
        .expect("32-byte seed");
    SigningState::from_seed(seed, "1").expect("signer")
}

fn pk_r() -> Vec<u8> {
    vector_hex(&vectors()["key_conversion"][0], "pkR")
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .expect("ascii header")
}

fn signature_verifies(headers: &HeaderMap, outer_req: &[u8], outer_resp: &[u8]) -> bool {
    let pubkey: [u8; 32] = h(header(headers, "vrpc-pubkey")
        .strip_prefix("0x")
        .expect("0x pubkey"))
    .try_into()
    .expect("32-byte pubkey");
    let signature: [u8; 64] = h(header(headers, "vrpc-signature")
        .strip_prefix("0x")
        .expect("0x signature"))
    .try_into()
    .expect("64-byte signature");
    let ts: u64 = header(headers, "vrpc-timestamp")
        .parse()
        .expect("numeric timestamp");
    let pre_image = build_pre_image(&sha256(b"1"), &sha256(outer_req), &sha256(outer_resp), ts);
    VerifyingKey::from_bytes(&pubkey)
        .expect("pubkey")
        .verify(&pre_image, &signature.into())
        .is_ok()
}

fn assert_signature(headers: &HeaderMap, outer_req: &[u8], outer_resp: &[u8]) {
    assert!(
        signature_verifies(headers, outer_req, outer_resp),
        "signature verifies"
    );
}

const BAD_REQUEST_BODY: &[u8] = br#"{"type":"urn:vrpc:error:bad-request","title":"Bad request"}"#;
const UNSUPPORTED_MEDIA_TYPE_BODY: &[u8] =
    br#"{"type":"urn:vrpc:error:unsupported-media-type","title":"Unsupported media type"}"#;

fn cfg() -> ConfidentialConfig {
    ConfidentialConfig {
        max_request_bytes: 8 * 1024 * 1024,
        max_response_bytes: usize::MAX,
    }
}

fn outer(body: Vec<u8>) -> Request {
    Request::builder()
        .method("POST")
        .uri("/confidential?node_id=7&x=y")
        .header("content-type", "message/ohttp-req")
        .header("authorization", "Bearer outer")
        .header("x-api-key", "outer")
        .body(Body::from(body))
        .expect("outer request")
}

async fn run(upstream_url: &str, body: Vec<u8>) -> (u16, HeaderMap, Vec<u8>) {
    run_with(upstream_url, cfg(), body).await
}

async fn run_with(
    upstream_url: &str,
    cfg: ConfidentialConfig,
    body: Vec<u8>,
) -> (u16, HeaderMap, Vec<u8>) {
    let upstream = UpstreamClient::new(upstream_url.into(), None).expect("upstream client");
    let resp = confidential_exchange(&upstream, &signer(), &cfg, outer(body)).await;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, headers, body.to_vec())
}

async fn assert_sealed_error(upstream_url: &str, plaintext: &[u8], status: u16, body: &[u8]) {
    assert_sealed_error_with(upstream_url, cfg(), plaintext, status, body).await;
}

async fn assert_sealed_error_with(
    upstream_url: &str,
    cfg: ConfidentialConfig,
    plaintext: &[u8],
    status: u16,
    body: &[u8],
) {
    let (outer_req, client) = seal(&pk_r(), plaintext);
    let (outer_status, headers, outer_resp) = run_with(upstream_url, cfg, outer_req.clone()).await;
    assert_eq!(outer_status, status);
    assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
    assert_signature(&headers, &outer_req, &outer_resp);
    let inner = inner_response(&client, &outer_resp);
    assert_eq!(inner.control().status().map(|s| s.code()), Some(status));
    assert_eq!(
        inner_fields(&inner),
        [(
            b"content-type".to_vec(),
            b"application/problem+json".to_vec()
        )]
    );
    assert_eq!(inner.content(), body);
}

fn long_path(len: usize) -> Vec<u8> {
    let mut path = b"/".to_vec();
    path.resize(len, b'a');
    path
}

#[tokio::test]
async fn invalid_inner_requests_are_sealed_400_and_never_reach_upstream() {
    let (url, upstream) = mock(OK_REPLY).await;
    let json: (&[u8], &[u8]) = (b"content-type", b"application/json");
    let body: &[u8] = b"{\"x\":1}";
    let framed = |framing: &[u8]| {
        encode_request(
            framing,
            b"POST",
            b"https",
            b"localhost",
            b"/",
            &[json],
            body,
            &[],
        )
    };
    let with_path = |path: &[u8]| bhttp_request(b"POST", path, &[json], body);
    let mut wide = b"/".to_vec();
    for _ in 0..40_000 {
        wide.extend_from_slice("é".as_bytes());
    }
    wide.extend_from_slice(b"a?q");
    let cases: Vec<Vec<u8>> = vec![
        framed(&[0x01]),
        framed(&[0x02]),
        framed(&[0x03]),
        framed(&[0x40, 0x00]),
        Vec::new(),
        vec![0x00],
        bhttp_request(b"", b"/", &[json], body),
        bhttp_request(b"GE T", b"/", &[json], body),
        bhttp_request(b"CONNECT", b"/", &[json], body),
        bhttp_request(
            b"POST",
            b"/",
            &[json, (b":authority", b"evil.example")],
            body,
        ),
        bhttp_request(b"POST", b"/", &[json, (b":path", b"/x")], body),
        bhttp_request(b"POST", b"/", &[json, json], body),
        bhttp_request(
            b"POST",
            b"/",
            &[(b"Content-Type", b"application/json"), json],
            body,
        ),
        bhttp_request(
            b"POST",
            b"/",
            &[(b"content-type", b"application/json\x01")],
            body,
        ),
        bhttp_request(b"POST", b"/", &[json, (b"accept", b"text/plain\x7f")], body),
        with_path(b"@evil.example/x"),
        with_path(b"//evil.example"),
        with_path(b"http://x/"),
        with_path(b"x"),
        with_path(b""),
        with_path(b"/a#b"),
        with_path(b"/a b"),
        with_path(&long_path(65_535)),
        with_path(&wide),
    ];
    assert_eq!(wide.len(), 80_004);
    for plaintext in &cases {
        assert_sealed_error(&url, plaintext, 400, BAD_REQUEST_BODY).await;
    }
    assert_eq!(upstream.conns(), 0);
}

#[tokio::test]
async fn body_without_content_type_is_sealed_415() {
    let (url, upstream) = mock(OK_REPLY).await;
    assert_sealed_error(
        &url,
        &bhttp_request(b"POST", b"/x", &[], b"{\"x\":1}"),
        415,
        UNSUPPORTED_MEDIA_TYPE_BODY,
    )
    .await;
    assert_sealed_error(
        &url,
        &bhttp_request(b"POST", b"x", &[], b"{\"x\":1}"),
        400,
        BAD_REQUEST_BODY,
    )
    .await;
    assert_eq!(upstream.conns(), 0);

    let (outer_req, _) = seal(&pk_r(), &bhttp_request(b"GET", b"/x", &[], b""));
    let (status, _, _) = run(&url, outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(upstream.conns(), 1);
    let seen = upstream.request(0);
    assert_eq!(seen.line, "GET /x HTTP/1.1");
    assert!(!seen.names().contains(&"content-type"));
}

#[tokio::test]
async fn upstream_receives_only_allowed_inner_fields() {
    let (url, upstream) = mock(OK_REPLY).await;
    let plaintext = encode_request(
        &[0x00],
        b"POST",
        b"http",
        b"evil.example:1",
        b"/rpc?a=1",
        &[
            (b"CONTENT-TYPE", b"application/json"),
            (b"accept", b"a/1"),
            (b"Host", b"evil.example"),
            (b"Authorization", b"Bearer inner"),
            (b"Cookie", b"c=1"),
            (b"Content-Encoding", b"gzip"),
            (b"Transfer-Encoding", b"chunked"),
            (b"Content-Length", b"999"),
            (b"Expect", b"100-continue"),
            (b"X-Custom", b"1"),
            (b"Accept", b"b/2"),
        ],
        b"{\"x\":1}",
        &[(b"x-trailer", b"1")],
    );
    let (outer_req, _) = seal(&pk_r(), &plaintext);
    let (status, _, _) = run(&url, outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(upstream.conns(), 1);
    let seen = upstream.request(0);
    assert_eq!(seen.line, "POST /rpc?a=1 HTTP/1.1");
    assert_eq!(
        seen.names(),
        [
            "content-type",
            "accept",
            "accept",
            "accept-encoding",
            "host",
            "content-length"
        ]
    );
    assert_eq!(
        seen.values(),
        [
            b"application/json".as_slice(),
            b"a/1",
            b"b/2",
            b"identity",
            url.trim_start_matches("http://").as_bytes(),
            b"7",
        ]
    );
    assert_eq!(seen.body, b"{\"x\":1}");
}

#[tokio::test]
async fn extension_methods_are_forwarded_verbatim() {
    for method in ["PURGE", "connect"] {
        let (url, upstream) = mock(OK_REPLY).await;
        let (outer_req, _) = seal(&pk_r(), &bhttp_request(method.as_bytes(), b"/x", &[], b""));
        let (status, _, _) = run(&url, outer_req).await;
        assert_eq!(status, 200);
        assert_eq!(upstream.conns(), 1);
        assert_eq!(upstream.request(0).line, format!("{method} /x HTTP/1.1"));
    }
}

#[tokio::test]
async fn path_limit_includes_configured_base_path() {
    let (url, upstream) = mock(OK_REPLY).await;
    let (outer_req, _) = seal(
        &pk_r(),
        &bhttp_request(b"GET", &long_path(65_530), &[], b""),
    );
    let (status, _, _) = run(&format!("{url}/api"), outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(upstream.conns(), 1);
    assert!(upstream.request(0).line.starts_with("GET /api/a"));

    let (url, upstream) = mock(OK_REPLY).await;
    assert_sealed_error(
        &format!("{url}/api"),
        &bhttp_request(b"GET", &long_path(65_531), &[], b""),
        400,
        BAD_REQUEST_BODY,
    )
    .await;
    assert_eq!(upstream.conns(), 0);

    let (url, upstream) = mock(OK_REPLY).await;
    let (outer_req, _) = seal(
        &pk_r(),
        &bhttp_request(b"GET", &long_path(65_534), &[], b""),
    );
    let (status, _, _) = run(&url, outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(upstream.conns(), 1);
}

#[test]
fn origin_uri_keeps_base_path_and_ignores_base_query() {
    let upstream =
        UpstreamClient::new("http://127.0.0.1:9/api/v2?q=1".into(), None).expect("client");
    let path_and_query = upstream
        .origin_path_and_query(b"/x?y=2")
        .expect("path and query");
    assert_eq!(
        upstream
            .origin_uri(path_and_query)
            .expect("uri")
            .to_string(),
        "http://127.0.0.1:9/api/v2/x?y=2"
    );
    assert!(upstream.origin_path_and_query(&long_path(65_535)).is_none());
    assert!(upstream.origin_path_and_query(b"/a b").is_none());
}

#[test]
fn decode_inner_never_panics_on_random_bytes() {
    let mut buf = [0u8; 64];
    let mut len = [0u8; 1];
    for i in 0..200_000u32 {
        getrandom::fill(&mut buf).expect("os rng");
        getrandom::fill(&mut len).expect("os rng");
        if i % 2 == 0 {
            buf[0] = 0x00;
        }
        let _ = decode_inner(&buf[..usize::from(len[0] % 64)]);
    }
}

const UPSTREAM_ERROR_BODY: &[u8] =
    br#"{"type":"urn:vrpc:error:upstream","title":"Upstream error"}"#;

fn reply(status: &str, headers: &[&str], body: &[u8]) -> &'static [u8] {
    let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n").into_bytes();
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    Box::leak(out.into_boxed_slice())
}

struct Exchange {
    status: u16,
    headers: HeaderMap,
    outer_req: Vec<u8>,
    outer_resp: Vec<u8>,
    client: ClientCtx,
}

async fn sealed_get(upstream_url: &str) -> Exchange {
    let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let (status, headers, outer_resp) = run(upstream_url, outer_req.clone()).await;
    assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
    assert_signature(&headers, &outer_req, &outer_resp);
    Exchange {
        status,
        headers,
        outer_req,
        outer_resp,
        client,
    }
}

#[tokio::test]
async fn upstream_failures_and_odd_statuses_are_sealed_502() {
    let mut small = cfg();
    small.max_response_bytes = 8;
    let short: &'static [u8] = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"result\":1}\n";
    let cases: Vec<(Option<&'static [u8]>, ConfidentialConfig)> = vec![
        (None, cfg()),
        (
            Some(b"HTTP/1.1 600 X\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"),
            cfg(),
        ),
        (
            Some(reply(
                "200 OK",
                &["Content-Type: application/json", "Content-Encoding: gzip"],
                OK_BODY,
            )),
            cfg(),
        ),
        (Some(OK_REPLY), small),
        (Some(short), cfg()),
    ];
    for (upstream_reply, cfg) in cases {
        let url = match upstream_reply {
            Some(r) => mock(r).await.0,
            None => "http://127.0.0.1:1".to_owned(),
        };
        assert_sealed_error_with(
            &url,
            cfg,
            &bhttp_request(b"GET", b"/", &[], b""),
            502,
            UPSTREAM_ERROR_BODY,
        )
        .await;
    }
}

#[tokio::test]
async fn node_statuses_and_errors_are_relayed() {
    let rpc_error: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"internal error"}}"#;
    type Relayed<'a> = (&'static [u8], u16, &'a [u8], &'a [u8]);
    let cases: [Relayed; 4] = [
        (
            reply("599 X", &["Content-Type: text/plain"], b"x"),
            599,
            b"text/plain",
            b"x",
        ),
        (
            reply(
                "500 Internal Server Error",
                &["Content-Type: application/json"],
                rpc_error,
            ),
            500,
            b"application/json",
            rpc_error,
        ),
        (
            reply("404 Not Found", &["Content-Type: text/plain"], b"not found"),
            404,
            b"text/plain",
            b"not found",
        ),
        (
            reply(
                "200 OK",
                &[
                    "Content-Type: application/json",
                    "Content-Encoding: IDENTITY",
                ],
                OK_BODY,
            ),
            200,
            b"application/json",
            OK_BODY,
        ),
    ];
    for (upstream_reply, status, content_type, body) in cases {
        let (url, upstream) = mock(upstream_reply).await;
        let x = sealed_get(&url).await;
        assert_eq!(upstream.conns(), 1);
        assert_eq!(x.status, status);
        let inner = inner_response(&x.client, &x.outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(status));
        assert_eq!(
            inner_fields(&inner),
            [(b"content-type".to_vec(), content_type.to_vec())]
        );
        assert_eq!(inner.content(), body);
    }
}

#[tokio::test]
async fn no_body_statuses_travel_as_outer_200() {
    let cases: [(&'static [u8], u16); 3] = [
        (b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n", 204),
        (
            b"HTTP/1.1 205 Reset Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            205,
        ),
        (
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n",
            304,
        ),
    ];
    for (upstream_reply, status) in cases {
        let (url, _) = mock(upstream_reply).await;
        let x = sealed_get(&url).await;
        assert_eq!(x.status, 200);
        let inner = inner_response(&x.client, &x.outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(status));
    }
}

#[tokio::test]
async fn node_response_is_reduced_to_status_content_type_and_body() {
    let (url, _) = mock(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await;
    let x = sealed_get(&url).await;
    assert_eq!(x.status, 200);
    let inner = inner_response(&x.client, &x.outer_resp);
    assert!(inner_fields(&inner).is_empty());
    assert!(inner.content().is_empty());

    let (url, _) = mock(reply(
        "200 OK",
        &[
            "Content-Type: application/json",
            "Content-Type: text/plain",
            "Server: node",
            "X-Leak: 1",
            "Date: Thu, 01 Jan 1970 00:00:00 GMT",
            "Set-Cookie: s=1",
        ],
        OK_BODY,
    ))
    .await;
    let x = sealed_get(&url).await;
    assert_eq!(x.status, 200);
    let inner = inner_response(&x.client, &x.outer_resp);
    assert_eq!(
        inner_fields(&inner),
        [
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"content-type".to_vec(), b"text/plain".to_vec()),
        ]
    );
    assert_eq!(inner.content(), OK_BODY);
    let mut names: Vec<&str> = x.headers.keys().map(|k| k.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "content-type",
            "vrpc-pubkey",
            "vrpc-signature",
            "vrpc-timestamp"
        ]
    );
    assert_eq!(x.headers.len(), 4);
}

#[tokio::test]
async fn replayed_request_gets_fresh_nonce_and_valid_signatures() {
    let (url, upstream) = mock(OK_REPLY).await;
    let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let mut replies = Vec::new();
    for _ in 0..2 {
        replies.push(run(&url, outer_req.clone()).await);
    }
    assert_eq!(upstream.conns(), 2);
    let sent = upstream.replied_at_ms.lock().expect("mock lock").clone();
    assert_eq!(sent.len(), 2);
    for ((status, headers, body), sent_at) in replies.iter().zip(sent) {
        assert_eq!(*status, 200);
        assert_signature(headers, &outer_req, body);
        let ts: u64 = header(headers, "vrpc-timestamp")
            .parse()
            .expect("numeric timestamp");
        assert!(ts >= sent_at, "timestamp {ts} precedes the reply {sent_at}");
    }
    let (first, second) = (&replies[0].2, &replies[1].2);
    assert_ne!(first[..32], second[..32]);
    assert_eq!(
        open_response(&client, first),
        open_response(&client, second)
    );
}

#[tokio::test]
async fn signature_covers_outer_bytes_only() {
    let (url, _) = mock(OK_REPLY).await;
    let x = sealed_get(&url).await;
    assert_eq!(x.status, 200);
    let inner_req = bhttp_request(b"GET", b"/", &[], b"");
    let inner_resp = open_response(&x.client, &x.outer_resp);
    assert!(signature_verifies(&x.headers, &x.outer_req, &x.outer_resp));
    assert!(!signature_verifies(&x.headers, &inner_req, &inner_resp));
    assert!(!signature_verifies(&x.headers, &x.outer_req, &inner_resp));
}

mod router {
    use super::*;
    use crate::server::build_router;
    use http_body_util::BodyExt;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    async fn serve(state: AppState, max_body: Option<usize>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind router");
        let addr = listener.local_addr().expect("router addr");
        let app = build_router(state, max_body);
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        format!("http://{addr}")
    }

    async fn call(
        method: &str,
        url: String,
        accept_encoding: &str,
        body: Vec<u8>,
    ) -> (u16, HeaderMap, Vec<u8>) {
        let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
        let req = hyper::Request::builder()
            .method(method)
            .uri(url)
            .header("content-type", "message/ohttp-req")
            .header("authorization", "Bearer outer")
            .header("x-api-key", "outer")
            .header("accept-encoding", accept_encoding)
            .body(Full::new(Bytes::from(body)))
            .expect("request");
        let resp = client.request(req).await.expect("router call");
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("router body")
            .to_bytes();
        (status, headers, body.to_vec())
    }

    #[tokio::test]
    async fn sealed_request_round_trips_through_router() {
        let (url, upstream) = mock(OK_REPLY).await;
        let base = serve(
            AppState::for_test(
                UpstreamClient::new(url.clone(), None).expect("upstream client"),
                signer(),
            ),
            None,
        )
        .await;
        let plaintext = bhttp_request(
            b"POST",
            b"/rpc?a=1",
            &[
                (b"Content-Type", b"application/json"),
                (b"accept", b"application/json"),
            ],
            b"{\"x\":1}",
        );
        let (outer_req, client) = seal(&pk_r(), &plaintext);

        let (status, headers, outer_resp) = call(
            "POST",
            format!("{base}/confidential?node_id=7&x=y"),
            "gzip",
            outer_req.clone(),
        )
        .await;

        assert_eq!(upstream.conns(), 1);
        let seen = upstream.request(0);
        assert_eq!(seen.line, "POST /rpc?a=1 HTTP/1.1");
        assert_eq!(
            seen.names(),
            [
                "content-type",
                "accept",
                "accept-encoding",
                "host",
                "content-length"
            ]
        );
        let authority = url.trim_start_matches("http://");
        assert_eq!(
            seen.values(),
            [
                b"application/json".as_slice(),
                b"application/json",
                b"identity",
                authority.as_bytes(),
                b"7",
            ]
        );
        assert_eq!(seen.body, b"{\"x\":1}");

        assert_eq!(status, 200);
        let mut names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "content-length",
                "content-type",
                "date",
                "vrpc-pubkey",
                "vrpc-signature",
                "vrpc-timestamp"
            ]
        );
        assert_eq!(header(&headers, "content-type"), "message/ohttp-res");

        let decrypted = open_response(&client, &outer_resp);
        assert_eq!(outer_resp.len(), 32 + decrypted.len() + 16);
        let inner = inner_response(&client, &outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(200));
        assert_eq!(
            inner_fields(&inner),
            [(b"content-type".to_vec(), b"application/json".to_vec())]
        );
        assert_eq!(inner.content(), OK_BODY);

        assert_eq!(header(&headers, "vrpc-pubkey"), signer().pubkey_hex());
        for name in ["vrpc-pubkey", "vrpc-signature"] {
            let value = header(&headers, name);
            assert!(value.starts_with("0x"));
            assert_eq!(value, value.to_ascii_lowercase());
        }
        assert_signature(&headers, &outer_req, &outer_resp);
    }
}
