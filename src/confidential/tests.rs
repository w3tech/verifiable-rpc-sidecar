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
        max_batch_size: 1000,
        upstream_timeout: std::time::Duration::from_secs(25),
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

fn tiny_fields(section_len: usize) -> Vec<(&'static [u8], &'static [u8])> {
    (0..section_len / 3)
        .map(|i| {
            let value: &[u8] = if i < section_len % 3 { b"b" } else { b"" };
            (b"a".as_slice(), value)
        })
        .collect()
}

#[tokio::test]
async fn field_sections_over_64_kib_are_sealed_400_and_never_reach_upstream() {
    let (url, upstream) = mock(OK_REPLY).await;
    let fields = tiny_fields(64 * 1024 + 1);
    assert_eq!(field_section(&fields).len(), 65_537);
    let header = bhttp_request(b"GET", b"/", &fields, b"");
    let trailer = encode_request(
        &[0x00],
        b"GET",
        b"https",
        b"localhost",
        b"/",
        &[],
        b"",
        &fields,
    );
    for plaintext in [header, trailer] {
        assert_sealed_error(&url, &plaintext, 400, BAD_REQUEST_BODY).await;
    }
    assert_eq!(upstream.conns(), 0);
}

#[tokio::test]
async fn header_section_of_exactly_64_kib_reaches_upstream() {
    let (url, upstream) = mock(OK_REPLY).await;
    let fields = tiny_fields(64 * 1024);
    assert_eq!(field_section(&fields).len(), 65_536);
    let (outer_req, _) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &fields, b""));
    let (status, _, _) = run(&url, outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(upstream.conns(), 1);
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

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

fn decode_without_panic(input: &[u8], case: std::fmt::Arguments) -> Option<InnerError> {
    match std::panic::catch_unwind(|| decode_inner(input).err()) {
        Ok(err) => err,
        Err(_) => panic!("decode_inner panicked on {case}: {input:02x?}"),
    }
}

fn varint_of_width(value: u64, width: u32) -> Vec<u8> {
    let bits = 8 * width - 2;
    let prefix = u64::from(width.trailing_zeros()) << bits;
    let value = value.min((1 << bits) - 1) | prefix;
    value.to_be_bytes()[(8 - width as usize)..].to_vec()
}

#[test]
fn decode_inner_never_panics_on_seeded_random_bytes_or_long_lengths() {
    const SEED: u64 = 0x5eed_c0de_2026_1015;
    let mut rng = SplitMix64(SEED);
    for i in 0..200_000u32 {
        let len = (rng.next_u64() % 64) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        if i % 2 == 0 && !buf.is_empty() {
            buf[0] = 0x00;
        }
        decode_without_panic(&buf, format_args!("seed {SEED:#x} case {i}"));
    }

    let header = field_section(&[(b"accept", b"*/*")]);
    let segments: [&[u8]; 7] = [b"GET", b"https", b"localhost", b"/", &header, b"{}", b""];
    let tail = [b'a'; 16];
    let remaining = tail.len() as u64;
    for at in 0..segments.len() {
        let mut prefix = vec![0x00];
        for segment in &segments[..at] {
            vec_(segment, &mut prefix);
        }
        for width in [1, 2, 4, 8] {
            for declared in [remaining, remaining + 1, u64::MAX] {
                let varint = varint_of_width(declared, width);
                let mut input = prefix.clone();
                input.extend_from_slice(&varint);
                input.extend_from_slice(&tail);
                let err = decode_without_panic(&input, format_args!("length {varint:02x?}"));
                if declared > remaining {
                    assert_eq!(err, Some(InnerError::BadRequest), "length {varint:02x?}");
                }
                for cut in 1..varint.len() {
                    let mut input = prefix.clone();
                    input.extend_from_slice(&varint[..cut]);
                    let err = decode_without_panic(&input, format_args!("cut {varint:02x?}"));
                    assert_eq!(err, Some(InnerError::BadRequest), "cut {varint:02x?}");
                }
            }
        }
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
            "vrpc-batch-size",
            "vrpc-pubkey",
            "vrpc-signature",
            "vrpc-timestamp"
        ]
    );
    assert_eq!(x.headers.len(), 5);
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

const OHTTP_KEY_PROBLEM_BODY: &[u8] = br#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}"#;

fn assert_no_vrpc_header(headers: &HeaderMap) {
    assert!(!headers.keys().any(|k| k.as_str().starts_with("vrpc-")));
}

#[tokio::test]
async fn pre_decapsulation_failures_are_identical_and_never_reach_upstream() {
    let (url, upstream) = mock(OK_REPLY).await;
    let (b, _) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let patched = |at: usize, bytes: &[u8]| {
        let mut c = b.clone();
        c[at..at + bytes.len()].copy_from_slice(bytes);
        c
    };
    let flipped = |at: usize| {
        let mut c = b.clone();
        c[at] ^= 0x01;
        c
    };
    let mut hdr_then_zeros = vector_hex(&env0(), "hdr");
    hdr_then_zeros.resize(55, 0);
    let cases = vec![
        Vec::new(),
        b[..54].to_vec(),
        hdr_then_zeros,
        patched(0, &[0x01]),
        patched(1, &[0x00, 0x21]),
        patched(3, &[0x00, 0x02]),
        patched(5, &[0x00, 0x01]),
        patched(7, &[0u8; 32]),
        flipped(40),
        flipped(b.len() - 1),
    ];
    assert_eq!(cases.len(), 10);
    assert_eq!(cases[2].len(), 55);
    assert!(cases.iter().skip(3).all(|c| c != &b));
    let mut replies = Vec::new();
    for body in cases {
        let (status, headers, resp) = run(&url, body).await;
        assert_eq!(status, 400);
        assert_eq!(headers.len(), 1);
        assert_eq!(header(&headers, "content-type"), "application/problem+json");
        assert_no_vrpc_header(&headers);
        assert_eq!(resp.len(), 126);
        assert_eq!(resp, OHTTP_KEY_PROBLEM_BODY);
        replies.push((status, headers, resp));
    }
    assert!(replies.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(upstream.conns(), 0);
}

#[tokio::test]
async fn inner_error_vector_is_reproduced() {
    let e = vectors()["envelopes"][1].clone();
    assert_eq!(e["name"], "inner-error-bad-request");
    let bhttp_response = vector_hex(&e, "bhttp_response");
    assert_eq!(
        decode_inner(&vector_hex(&e, "bhttp_request")).err(),
        Some(InnerError::BadRequest)
    );
    assert_eq!(
        encode_response(&InnerError::BadRequest.into()),
        Some(bhttp_response.clone())
    );

    let (url, upstream) = mock(OK_REPLY).await;
    let outer_req = vector_hex(&e, "encapsulated_request");
    let (status, headers, outer_resp) = run(&url, outer_req.clone()).await;
    assert_eq!(Some(u64::from(status)), e["outer_status"].as_u64());
    assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
    let go = ClientCtx {
        enc: vector_hex(&e, "enc"),
        secret: vector_hex(&e, "export_secret")
            .try_into()
            .expect("32-byte secret"),
    };
    assert_eq!(open_response(&go, &outer_resp), bhttp_response);
    assert_signature(&headers, &outer_req, &outer_resp);
    assert_eq!(upstream.conns(), 0);
}

#[tokio::test]
async fn request_cap_is_inclusive_and_over_cap_is_bare_413() {
    let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let len = outer_req.len();

    let (url, upstream) = mock(OK_REPLY).await;
    let mut at_cap = cfg();
    at_cap.max_request_bytes = len;
    let (status, headers, body) = run_with(&url, at_cap, outer_req.clone()).await;
    assert_eq!(status, 200);
    assert_signature(&headers, &outer_req, &body);
    assert_eq!(inner_response(&client, &body).content(), OK_BODY);
    assert_eq!(upstream.conns(), 1);

    let (url, upstream) = mock(OK_REPLY).await;
    let mut below = cfg();
    below.max_request_bytes = len - 1;
    let (status, headers, body) = run_with(&url, below, outer_req).await;
    assert_eq!(status, 413);
    assert!(body.is_empty());
    assert!(headers.get("content-type").is_none());
    assert_no_vrpc_header(&headers);
    assert_eq!(upstream.conns(), 0);
}

#[test]
fn batch_size_matches_the_node_parser() {
    let fixed: &[(&[u8], usize)] = &[
        (br#"{"a":1}"#, 1),
        (b"[1,2,3]", 3),
        (b"\t\r\n [1,2,3]", 3),
        (b"[]", 1),
        (b" \n\r\t[ ]", 1),
        (b"\x0c[1,2]", 1),
        (b"[\x0c1]", 1),
        (b"[1,2,3]garbage[", 3),
        (b"[1,2][3,4,5]", 2),
        (b"[1,2,]", 1),
        (b"[1,2,", 1),
        (b"[01,2]", 1),
        (b"\xef\xbb\xbf[1,2]", 1),
        (b"[\"\x80\xff\",1]", 2),
        (b"[1\xff,2]", 1),
        (br#"["\ud800",1]"#, 2),
        (b"[\"a\x01b\",1]", 1),
        (br#"[1,"t",null,true]"#, 4),
        (br#"[[[1]],{"a":[]}]"#, 2),
        (b"null", 1),
        (b"", 1),
    ];
    let mut cases: Vec<(Vec<u8>, usize)> = fixed.iter().map(|(b, n)| (b.to_vec(), *n)).collect();
    let mut ones = b"[1".to_vec();
    ones.extend(b",1".repeat(1000));
    ones.push(b']');
    cases.push((ones, 1001));
    for depth in [9_998, 10_000, 1_000_000] {
        let mut nested = b"[".to_vec();
        nested.extend(b"[".repeat(depth));
        nested.extend(b"]".repeat(depth));
        nested.extend(b",1]");
        cases.push((nested, 2));
    }
    for (i, (body, expected)) in cases.iter().enumerate() {
        assert_eq!(batch_size(body), *expected, "case {i}");
    }
}

fn batch(n: usize) -> Vec<u8> {
    let calls: Vec<String> = (1..=n)
        .map(|id| format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"eth_chainId","params":[]}}"#))
        .collect();
    format!("[{}]", calls.join(",")).into_bytes()
}

fn sealed_json(path: &[u8], body: &[u8]) -> (Vec<u8>, ClientCtx) {
    seal(
        &pk_r(),
        &bhttp_request(
            b"POST",
            path,
            &[(b"content-type", b"application/json")],
            body,
        ),
    )
}

async fn assert_batch_forwarded(cfg: ConfidentialConfig, n: usize) {
    let (url, upstream) = mock(OK_REPLY).await;
    let body = batch(n);
    let (outer_req, client) = sealed_json(b"/", &body);
    let (status, headers, outer_resp) = run_with(&url, cfg, outer_req.clone()).await;
    assert_eq!(status, 200, "{n}");
    assert_eq!(header(&headers, "vrpc-batch-size"), n.to_string());
    assert_signature(&headers, &outer_req, &outer_resp);
    assert_eq!(upstream.conns(), 1);
    assert_eq!(upstream.request(0).body, body);
    assert_eq!(inner_response(&client, &outer_resp).content(), OK_BODY);
}

async fn assert_batch_too_large(cfg: ConfidentialConfig, n: usize) {
    let (url, upstream) = mock(OK_REPLY).await;
    let (outer_req, client) = sealed_json(b"/", &batch(n));
    let (status, headers, outer_resp) = run_with(&url, cfg, outer_req.clone()).await;
    assert_eq!(status, 413, "{n}");
    assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
    assert_eq!(header(&headers, "vrpc-batch-size"), n.to_string());
    assert_signature(&headers, &outer_req, &outer_resp);
    let inner = inner_response(&client, &outer_resp);
    assert_eq!(inner.control().status().map(|s| s.code()), Some(413));
    assert_eq!(
        inner_fields(&inner),
        [(
            b"content-type".to_vec(),
            b"application/problem+json".to_vec()
        )]
    );
    assert_eq!(
        inner.content(),
        br#"{"type":"urn:vrpc:error:batch-too-large","title":"Batch too large"}"#
    );
    assert_eq!(upstream.conns(), 0);
}

#[tokio::test]
async fn batch_at_the_limit_is_forwarded_and_one_more_is_sealed_413() {
    let mut three = cfg();
    three.max_batch_size = 3;
    assert_batch_forwarded(three, 3).await;
    assert_batch_too_large(three, 4).await;
    assert_batch_forwarded(cfg(), 1000).await;
    assert_batch_too_large(cfg(), 1001).await;
}

#[tokio::test]
async fn errors_before_counting_carry_batch_size_1() {
    let (url, upstream) = mock(OK_REPLY).await;
    let three = batch(3);
    let cases = [
        (
            bhttp_request(
                b"POST",
                b"@evil.example/x",
                &[(b"content-type", b"application/json")],
                &three,
            ),
            400,
            BAD_REQUEST_BODY,
        ),
        (
            bhttp_request(b"POST", b"/", &[], &three),
            415,
            UNSUPPORTED_MEDIA_TYPE_BODY,
        ),
    ];
    for (plaintext, status, body) in cases {
        assert_sealed_error(&url, &plaintext, status, body).await;
        let (outer_req, client) = seal(&pk_r(), &plaintext);
        let (outer_status, headers, outer_resp) = run(&url, outer_req).await;
        assert_eq!(outer_status, status);
        assert_eq!(header(&headers, "vrpc-batch-size"), "1", "{status}");
        let inner = inner_response(&client, &outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(status));
    }
    assert_eq!(upstream.conns(), 0);

    let (outer_req, client) = sealed_json(b"/", br#"{"a":1}"#);
    let (status, headers, outer_resp) = run(&url, outer_req).await;
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "vrpc-batch-size"), "1");
    assert_eq!(inner_response(&client, &outer_resp).content(), OK_BODY);
    assert_eq!(upstream.conns(), 1);

    let (outer_req, client) = sealed_json(b"/", &three);
    let (status, headers, outer_resp) = run("http://127.0.0.1:1", outer_req).await;
    assert_eq!(status, 502);
    assert_eq!(header(&headers, "vrpc-batch-size"), "3");
    let inner = inner_response(&client, &outer_resp);
    assert_eq!(inner.control().status().map(|s| s.code()), Some(502));
    assert_eq!(inner.content(), UPSTREAM_ERROR_BODY);
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
                "vrpc-batch-size",
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

    fn test_state(upstream_url: &str) -> AppState {
        AppState::for_test(
            UpstreamClient::new(upstream_url.into(), None).expect("upstream client"),
            signer(),
        )
    }

    #[tokio::test]
    async fn non_post_methods_get_405_without_upstream() {
        let (url, upstream) = mock(OK_REPLY).await;
        let base = serve(test_state(&url), None).await;
        for method in ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let (status, headers, body) =
                call(method, format!("{base}/confidential"), "gzip", Vec::new()).await;
            assert_eq!(status, 405, "{method}");
            assert!(header(&headers, "allow")
                .split(',')
                .any(|m| m.trim() == "POST"));
            assert!(body.is_empty());
            assert_no_vrpc_header(&headers);
        }
        assert_eq!(upstream.conns(), 0);
    }

    #[tokio::test]
    async fn pre_decapsulation_vectors_match_responses() {
        let (url, upstream) = mock(OK_REPLY).await;
        let mut state = test_state(&url);
        state.confidential.max_request_bytes = 16;
        let base = serve(state, None).await;
        let endpoint = format!("{base}/confidential");
        let v = vectors();
        let entries = v["pre_decapsulation_errors"]
            .as_array()
            .expect("pre_decapsulation_errors");
        let names: Vec<&str> = entries
            .iter()
            .map(|x| x["name"].as_str().expect("name"))
            .collect();
        assert_eq!(
            names,
            ["ohttp-key", "request-too-large", "method-not-allowed"]
        );
        assert_eq!(
            vector_hex(&entries[0], "body"),
            OHTTP_KEY_PROBLEM.as_bytes()
        );
        let sent = [
            ("POST", vec![0x5a; 10]),
            ("POST", vec![0x5a; 17]),
            ("GET", Vec::new()),
        ];
        for (x, (method, body)) in entries.iter().zip(sent) {
            let (status, headers, resp) = call(method, endpoint.clone(), "identity", body).await;
            assert_eq!(
                Some(u64::from(status)),
                x["status"].as_u64(),
                "{}",
                x["name"]
            );
            assert_eq!(
                headers
                    .get("content-type")
                    .map(|v| v.to_str().expect("ascii")),
                x["content_type"].as_str(),
                "{}",
                x["name"]
            );
            assert_eq!(resp, vector_hex(x, "body"), "{}", x["name"]);
        }
        assert_eq!(upstream.conns(), 0);
    }

    #[tokio::test]
    async fn confidential_responses_are_never_compressed() {
        let long_body: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (url, upstream) = mock(reply(
            "200 OK",
            &["Content-Type: application/json"],
            long_body,
        ))
        .await;
        let mut state = test_state(&url);
        state.confidential.max_request_bytes = 4096;
        let base = serve(state, None).await;
        let endpoint = format!("{base}/confidential");

        let (status, headers, body) = call("POST", endpoint.clone(), "gzip", vec![0x5a; 60]).await;
        assert_eq!(status, 400);
        assert_eq!(header(&headers, "content-length"), "126");
        assert!(headers.get("content-encoding").is_none());
        assert_eq!(body, OHTTP_KEY_PROBLEM_BODY);

        let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
        let (status, headers, body) = call("POST", endpoint.clone(), "gzip", outer_req).await;
        assert_eq!(status, 200);
        assert!(headers.get("content-encoding").is_none());
        assert_eq!(inner_response(&client, &body).content(), long_body);

        let (status, headers, _) = call("POST", endpoint, "gzip", vec![0; 5000]).await;
        assert_eq!(status, 413);
        assert!(headers.get("content-encoding").is_none());

        let (status, headers, _) = call("POST", format!("{base}/"), "gzip", b"{}".to_vec()).await;
        assert_eq!(status, 200);
        assert_eq!(header(&headers, "content-encoding"), "gzip");
        assert_eq!(upstream.conns(), 2);
    }

    #[tokio::test]
    async fn trailing_slash_and_case_variants_stay_on_passthrough() {
        let (url, upstream) = mock(OK_REPLY).await;
        let base = serve(test_state(&url), None).await;
        let (outer_req, _) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
        for (i, path) in ["/confidential/", "/Confidential"].into_iter().enumerate() {
            let (status, headers, body) = call(
                "POST",
                format!("{base}{path}"),
                "identity",
                outer_req.clone(),
            )
            .await;
            assert_eq!(upstream.conns(), i + 1, "{path}");
            assert_eq!(status, 200);
            assert_eq!(header(&headers, "content-type"), "application/json");
            assert_eq!(body, OK_BODY);
            let ts: u64 = header(&headers, "vrpc-timestamp")
                .parse()
                .expect("numeric timestamp");
            assert_eq!(
                header(&headers, "vrpc-signature"),
                signer()
                    .sign_with_timestamp(&outer_req, &body, ts)
                    .signature_hex()
            );
        }
    }

    #[tokio::test]
    async fn passthrough_body_limit_does_not_cut_confidential() {
        let (url, upstream) = mock(OK_REPLY).await;
        let mut state = AppState::for_test(
            UpstreamClient::new(url, Some(16)).expect("upstream client"),
            signer(),
        );
        state.confidential.max_response_bytes = 16;
        let base = serve(state, Some(16)).await;

        let (status, headers, body) = call(
            "POST",
            format!("{base}/confidential"),
            "identity",
            vec![0x5a; 1000],
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(header(&headers, "content-type"), "application/problem+json");
        assert_eq!(body, OHTTP_KEY_PROBLEM_BODY);

        let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
        let (status, headers, body) = call(
            "POST",
            format!("{base}/confidential"),
            "identity",
            outer_req.clone(),
        )
        .await;
        assert_eq!(status, 200);
        assert_signature(&headers, &outer_req, &body);
        assert_eq!(inner_response(&client, &body).content(), OK_BODY);
        assert_eq!(upstream.conns(), 1);

        let (status, _, _) = call("POST", format!("{base}/"), "identity", vec![0x5a; 1000]).await;
        assert_eq!(status, 413);
        assert_eq!(upstream.conns(), 1);
    }

    #[tokio::test]
    async fn sealed_batch_reaches_node_as_one_batch_with_its_size() {
        let (url, upstream) = mock(OK_REPLY).await;
        let base = serve(test_state(&url), None).await;
        let body: &[u8] = br#"[{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]},{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]},{"jsonrpc":"2.0","id":3,"method":"eth_blockNumber","params":[]}]"#;
        let plaintext = bhttp_request(
            b"POST",
            b"/",
            &[(b"content-type", b"application/json")],
            body,
        );
        let (outer_req, client) = seal(&pk_r(), &plaintext);

        let (status, headers, outer_resp) = call(
            "POST",
            format!("{base}/confidential"),
            "identity",
            outer_req.clone(),
        )
        .await;

        assert_eq!(status, 200);
        assert_eq!(header(&headers, "vrpc-batch-size"), "3");
        assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
        assert_signature(&headers, &outer_req, &outer_resp);
        assert_eq!(upstream.conns(), 1);
        assert_eq!(upstream.request(0).body, body);
        let inner = inner_response(&client, &outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(200));
        assert_eq!(inner.content(), OK_BODY);
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const MK_PATH: &[u8] = b"/mk-path-7f3a?mk-q=9c1e";
    const MK_CT: &[u8] = b"application/mk-ct-41d2";
    const MK_ACCEPT: &[u8] = b"mk-accept-55b0";
    const MK_BODY: &[u8] = br#"{"mk":"mk-body-e8a4"}"#;

    fn marked_request(path: &[u8], body: &[u8]) -> Vec<u8> {
        bhttp_request(
            b"POST",
            path,
            &[(b"content-type", MK_CT), (b"accept", MK_ACCEPT)],
            body,
        )
    }

    fn response_key_and_nonce(client: &ClientCtx, outer_resp: &[u8]) -> ([u8; 32], [u8; 12]) {
        let mut salt = client.enc.clone();
        salt.extend_from_slice(&outer_resp[..32]);
        let hk = Hkdf::<Sha256>::new(Some(&salt), &client.secret);
        let mut key = [0u8; 32];
        hk.expand(b"key", &mut key).expect("hkdf key");
        let mut nonce = [0u8; 12];
        hk.expand(b"nonce", &mut nonce).expect("hkdf nonce");
        (key, nonce)
    }

    #[tokio::test]
    async fn trace_capture_holds_one_outcome_line_per_call_and_no_content() {
        // With one registered dispatcher, callsites first hit on other test threads cache
        // `never`; a second live one makes them `sometimes`, checked per thread.
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let node_reply = reply(
            "200 OK",
            &["Content-Type: application/mk-resp-ct-2b7c"],
            b"mk-resp-body-90d1",
        );
        let (url, upstream) = mock(node_reply).await;
        let mut outer_reqs = Vec::new();

        let (ok_req, client) = seal(&pk_r(), &marked_request(MK_PATH, MK_BODY));
        outer_reqs.push(ok_req.clone());
        let (status, _, ok_resp) = run(&url, ok_req).await;
        assert_eq!(status, 200);
        assert_eq!(
            inner_response(&client, &ok_resp).content(),
            b"mk-resp-body-90d1"
        );

        let (req, _) = seal(&pk_r(), &marked_request(b"/mk-path-7f3a#frag", MK_BODY));
        outer_reqs.push(req.clone());
        assert_eq!(run(&url, req).await.0, 400);

        let mut one = cfg();
        one.max_batch_size = 1;
        let (req, _) = seal(&pk_r(), &marked_request(MK_PATH, b"[1,2]"));
        outer_reqs.push(req.clone());
        assert_eq!(run_with(&url, one, req).await.0, 413);

        let (req, _) = seal(&pk_r(), &marked_request(MK_PATH, MK_BODY));
        outer_reqs.push(req.clone());
        assert_eq!(run("http://127.0.0.1:1", req).await.0, 502);

        let (stalled, _) = stalled_mock(b"").await;
        let mut short = cfg();
        short.upstream_timeout = std::time::Duration::from_millis(300);
        let (req, _) = seal(&pk_r(), &marked_request(MK_PATH, MK_BODY));
        outer_reqs.push(req.clone());
        assert_eq!(run_with(&stalled, short, req).await.0, 504);

        let garbage: Vec<u8> = (0u8..60).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
        outer_reqs.push(garbage.clone());
        assert_eq!(run(&url, garbage).await.0, 400);

        let mut tiny = cfg();
        tiny.max_request_bytes = 16;
        let oversized = vec![0x3c; 17];
        outer_reqs.push(oversized.clone());
        assert_eq!(run_with(&url, tiny, oversized).await.0, 413);

        let base = serve(test_state(&url), None).await;
        let (status, _, _) = call(
            "GET",
            format!("{base}/confidential"),
            "identity",
            Vec::new(),
        )
        .await;
        assert_eq!(status, 405);

        assert_eq!(upstream.conns(), 1);
        assert!(upstream.request(0).line.contains("/mk-path-7f3a?mk-q=9c1e"));

        let text = String::from_utf8(capture.0.lock().expect("capture lock").clone())
            .expect("utf-8 capture");
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("confidential call"))
            .collect();
        assert_eq!(lines.len(), 8, "{lines:#?}");
        let line_of = |class: &str| {
            let quoted = format!("outcome=\"{class}\" ");
            let bare = format!("outcome={class} ");
            let found: Vec<&&str> = lines
                .iter()
                .filter(|l| l.contains(&quoted) || l.contains(&bare))
                .collect();
            assert_eq!(found.len(), 1, "{class}: {lines:#?}");
            *found[0]
        };
        for class in [
            "ok",
            "bad-request",
            "batch-too-large",
            "upstream",
            "upstream-timeout",
            "pre-decapsulation",
            "request-too-large",
            "method-not-allowed",
        ] {
            let line = line_of(class);
            for field in [
                "status=",
                "inner_status=",
                "batch_size=",
                "request_bytes=",
                "response_bytes=",
                "upstream_ms=",
                "total_ms=",
            ] {
                assert!(line.contains(field), "{class} lacks {field}");
            }
        }
        let batch = line_of("batch-too-large");
        assert!(batch.contains("batch_size=2 "), "{batch}");
        assert!(batch.contains("inner_status=413 "), "{batch}");
        let pre = line_of("pre-decapsulation");
        assert!(pre.contains("inner_status=0 "), "{pre}");
        assert!(pre.contains("batch_size=0 "), "{pre}");
        assert!(text.contains("hyper_util"));
        assert!(!text.contains("rpc_attest_sidecar::proxy"));

        for marker in [
            "mk-path-7f3a",
            "mk-q=9c1e",
            "mk-ct-41d2",
            "mk-accept-55b0",
            "mk-body-e8a4",
            "mk-resp-ct-2b7c",
            "mk-resp-body-90d1",
        ] {
            assert!(!text.contains(marker), "{marker}");
        }
        let keys = &vectors()["key_conversion"][0];
        let seed = vector_hex(keys, "seed");
        let sk_r = vector_hex(keys, "skR");
        let (aead_key, aead_nonce) = response_key_and_nonce(&client, &ok_resp);
        let mut hex_markers = vec![
            hex::encode(&seed),
            hex::encode(&sk_r),
            hex::encode(client.secret),
            hex::encode(aead_key),
            hex::encode(aead_nonce),
            hex::encode(&ok_resp[..16]),
        ];
        hex_markers.extend(outer_reqs.iter().map(|r| hex::encode(&r[..16])));
        let lower = text.to_lowercase();
        for marker in hex_markers {
            assert!(!lower.contains(&marker), "{marker}");
            assert!(!text.contains(&marker.to_uppercase()), "{marker}");
        }
        for secret in [&seed[..4], &sk_r[..4], &client.secret[..4]] {
            let debug = format!("{secret:?}");
            let open = debug.trim_end_matches(']');
            assert!(!text.contains(open), "{open}");
        }
    }
}

const UPSTREAM_TIMEOUT_BODY: &[u8] =
    br#"{"type":"urn:vrpc:error:upstream-timeout","title":"Upstream timeout"}"#;

#[derive(Default)]
struct StallMock {
    conns: AtomicUsize,
    received: Mutex<Vec<Vec<u8>>>,
    closed: AtomicUsize,
}

async fn stalled_mock(prefix: &'static [u8]) -> (String, Arc<StallMock>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let state = Arc::new(StallMock::default());
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
            if !prefix.is_empty() {
                let _ = stream.write_all(prefix).await;
            }
            let held = shared.clone();
            tokio::spawn(async move {
                while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
                held.closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (url, state)
}

async fn wait_closed(upstream: &StallMock) -> usize {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while upstream.closed.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    upstream.closed.load(Ordering::SeqCst)
}

#[tokio::test]
async fn stalled_upstream_headers_or_body_are_sealed_504() {
    use std::time::{Duration, Instant};

    let prefixes: [&'static [u8]; 2] = [
        b"",
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"partial",
    ];
    for prefix in prefixes {
        let (url, upstream) = stalled_mock(prefix).await;
        let mut c = cfg();
        c.upstream_timeout = Duration::from_millis(300);
        let (outer_req, client) = seal(
            &pk_r(),
            &bhttp_request(
                b"POST",
                b"/",
                &[(b"content-type", b"application/json")],
                b"[1,2]",
            ),
        );
        let started = Instant::now();
        let (status, headers, outer_resp) = run_with(&url, c, outer_req.clone()).await;
        let elapsed = started.elapsed();

        assert_eq!(status, 504);
        assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
        assert_signature(&headers, &outer_req, &outer_resp);
        let inner = inner_response(&client, &outer_resp);
        assert_eq!(inner.control().status().map(|s| s.code()), Some(504));
        assert_eq!(
            inner_fields(&inner),
            [(
                b"content-type".to_vec(),
                b"application/problem+json".to_vec()
            )]
        );
        assert_eq!(inner.content(), UPSTREAM_TIMEOUT_BODY);
        assert_eq!(header(&headers, "vrpc-batch-size"), "2");
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(upstream.conns.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.received.lock().expect("mock lock").len(), 1);
        assert_eq!(wait_closed(&upstream).await, 1);
    }
}

fn chunked_ok_reply() -> &'static [u8] {
    let mut out = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for chunk in [&OK_BODY[..6], &OK_BODY[6..]] {
        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    Box::leak(out.into_boxed_slice())
}

async fn relayed_with_cap(upstream_reply: &'static [u8], cap: usize) -> bhttp::Message {
    let (url, _) = mock(upstream_reply).await;
    let mut c = cfg();
    c.max_response_bytes = cap;
    let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let (status, headers, outer_resp) = run_with(&url, c, outer_req.clone()).await;
    assert_eq!(status, 200);
    assert_eq!(header(&headers, "content-type"), "message/ohttp-res");
    assert_signature(&headers, &outer_req, &outer_resp);
    let inner = inner_response(&client, &outer_resp);
    assert_eq!(inner.control().status().map(|s| s.code()), Some(200));
    inner
}

#[tokio::test]
async fn response_cap_is_inclusive_for_sized_and_chunked_bodies() {
    for upstream_reply in [OK_REPLY, chunked_ok_reply()] {
        let inner = relayed_with_cap(upstream_reply, OK_BODY.len()).await;
        assert_eq!(
            inner_fields(&inner),
            [(b"content-type".to_vec(), b"application/json".to_vec())]
        );
        assert_eq!(inner.content(), OK_BODY);

        let (url, _) = mock(upstream_reply).await;
        let mut c = cfg();
        c.max_response_bytes = OK_BODY.len() - 1;
        assert_sealed_error_with(
            &url,
            c,
            &bhttp_request(b"GET", b"/", &[], b""),
            502,
            UPSTREAM_ERROR_BODY,
        )
        .await;
    }

    let inner = relayed_with_cap(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        0,
    )
    .await;
    assert!(inner.content().is_empty());
}

#[tokio::test]
async fn status_encoding_and_length_are_checked_before_the_body() {
    use std::time::{Duration, Instant};

    let heads: [(&'static [u8], usize); 4] = [
        (
            b"HTTP/1.1 600 X\r\nConnection: close\r\nContent-Length: 100\r\n\r\n",
            usize::MAX,
        ),
        (
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Encoding: gzip\r\nContent-Length: 100\r\n\r\n",
            usize::MAX,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            usize::MAX,
        ),
        (
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 100\r\n\r\n",
            99,
        ),
    ];
    for (head, cap) in heads {
        let (url, upstream) = stalled_mock(head).await;
        let mut c = cfg();
        c.upstream_timeout = Duration::from_secs(10);
        c.max_response_bytes = cap;
        let started = Instant::now();
        assert_sealed_error_with(
            &url,
            c,
            &bhttp_request(b"GET", b"/", &[], b""),
            502,
            UPSTREAM_ERROR_BODY,
        )
        .await;
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert_eq!(upstream.conns.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn sealed_response_is_written_into_one_exact_buffer() {
    let (outer_req, client) = seal(&pk_r(), &bhttp_request(b"GET", b"/", &[], b""));
    let (_, ctx) = signer().open_request(&outer_req).expect("open request");
    let content = vec![0x5a; 1 << 20];
    let message = || {
        let mut msg = bhttp::Message::response(bhttp::StatusCode::try_from(200u16).expect("200"));
        msg.put_header("content-type", "application/json");
        msg.write_content(&content);
        msg
    };
    let mut expected = Vec::new();
    message()
        .write_bhttp(bhttp::Mode::KnownLength, &mut expected)
        .expect("encode");

    let nonce = [7u8; RESPONSE_NONCE_LEN];
    let mut buf = encode_with_nonce(message(), &nonce).expect("encode with nonce");
    assert_eq!(buf.len(), RESPONSE_NONCE_LEN + expected.len());
    assert_eq!(buf.capacity(), buf.len() + crate::envelope::TAG_LEN);
    ctx.seal_in_place(&mut buf).expect("seal in place");

    assert_eq!(
        buf.len(),
        RESPONSE_NONCE_LEN + expected.len() + crate::envelope::TAG_LEN
    );
    assert_eq!(buf.len(), buf.capacity());
    assert_eq!(buf.get(..RESPONSE_NONCE_LEN), Some(&nonce[..]));
    assert_eq!(open_response(&client, &buf), expected);
}

#[test]
fn outcome_classes_are_the_documented_strings() {
    let classes = [
        (OutcomeClass::Ok, "ok"),
        (OutcomeClass::BadRequest, "bad-request"),
        (OutcomeClass::UnsupportedMediaType, "unsupported-media-type"),
        (OutcomeClass::BatchTooLarge, "batch-too-large"),
        (OutcomeClass::Upstream, "upstream"),
        (OutcomeClass::UpstreamTimeout, "upstream-timeout"),
        (OutcomeClass::Internal, "internal"),
        (OutcomeClass::PreDecapsulation, "pre-decapsulation"),
        (OutcomeClass::RequestTooLarge, "request-too-large"),
        (OutcomeClass::MethodNotAllowed, "method-not-allowed"),
        (OutcomeClass::Unsealable, "unsealable"),
    ];
    for (class, s) in classes {
        assert_eq!(class.as_str(), s);
    }
    let errors = [
        (InnerError::BadRequest, OutcomeClass::BadRequest),
        (
            InnerError::UnsupportedMediaType,
            OutcomeClass::UnsupportedMediaType,
        ),
        (InnerError::BatchTooLarge, OutcomeClass::BatchTooLarge),
        (InnerError::Upstream, OutcomeClass::Upstream),
        (InnerError::UpstreamTimeout, OutcomeClass::UpstreamTimeout),
        (InnerError::Internal, OutcomeClass::Internal),
    ];
    for (e, class) in errors {
        assert_eq!(e.class(), class);
    }
}
