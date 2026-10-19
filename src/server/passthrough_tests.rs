// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

use std::io::Read as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderMap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{build_router, AppState};
use crate::proxy::UpstreamClient;
use crate::signing::SigningState;

#[derive(Default)]
struct Mock {
    conns: AtomicUsize,
    received: Mutex<Vec<Vec<u8>>>,
}

fn reply(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status_line}\r\nConnection: close\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
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

async fn mock(reply: Vec<u8>) -> (String, Arc<Mock>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let url = format!("http://{}", listener.local_addr().expect("mock addr"));
    let state = Arc::new(Mock::default());
    let shared = state.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            shared.conns.fetch_add(1, Ordering::SeqCst);
            let mut acc = Vec::new();
            let mut buf = [0u8; 4096];
            while !request_complete(&acc) {
                let n = stream.read(&mut buf).await.expect("read mock");
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
            }
            shared.received.lock().expect("mock lock").push(acc);
            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
        }
    });
    (url, state)
}

fn header_names(headers: &HeaderMap) -> Vec<String> {
    headers.keys().map(|k| k.as_str().to_owned()).collect()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .expect("ascii header")
}

fn signer() -> SigningState {
    SigningState::from_seed([7u8; 32], "1").expect("signer")
}

fn assert_signed(signer: &SigningState, headers: &HeaderMap, request: &[u8], response: &[u8]) {
    let ts: u64 = header_str(headers, "vrpc-timestamp")
        .parse()
        .expect("numeric timestamp");
    assert_eq!(header_str(headers, "vrpc-pubkey"), signer.pubkey_hex());
    assert_eq!(
        header_str(headers, "vrpc-signature"),
        signer
            .sign_with_timestamp(request, response, ts)
            .signature_hex()
    );
}

#[tokio::test]
async fn forward_response_is_pinned() {
    let body = b"{\"result\":1}\n";
    let (url, upstream) = mock(reply(
        "201 Created",
        &[
            ("Content-Type", "application/json"),
            ("Content-Encoding", "identity"),
            ("X-Custom", "a"),
            ("Server", "node"),
        ],
        body,
    ))
    .await;
    let client = UpstreamClient::new(url.clone(), None).expect("upstream client");
    let signer = signer();
    let req = Request::builder()
        .method("POST")
        .uri("/x?y=1")
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip")
        .header("x-trace", "t")
        .body(Body::from("{}"))
        .expect("request");

    let resp = client.forward(req, &signer).await;

    assert_eq!(resp.status().as_u16(), 201);
    let headers = resp.headers().clone();
    assert_eq!(
        header_names(&headers),
        [
            "content-type",
            "x-custom",
            "server",
            "content-length",
            "vrpc-signature",
            "vrpc-timestamp",
            "vrpc-pubkey",
        ]
    );
    let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(&got[..], body);
    assert_signed(&signer, &headers, b"{}", &got);

    assert_eq!(upstream.conns.load(Ordering::SeqCst), 1);
    let raw = upstream.received.lock().expect("mock lock")[0].clone();
    assert!(raw.starts_with(b"POST /x?y=1 HTTP/1.1\r\n"));
    let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    parsed.parse(&raw).expect("parse upstream request");
    let names: Vec<String> = parsed
        .headers
        .iter()
        .map(|h| h.name.to_ascii_lowercase())
        .collect();
    assert_eq!(
        names,
        [
            "content-type",
            "x-trace",
            "accept-encoding",
            "host",
            "content-length"
        ]
    );
    let value = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.to_vec())
            .expect("upstream header")
    };
    assert_eq!(value("accept-encoding"), b"identity");
    assert_eq!(value("host"), url.trim_start_matches("http://").as_bytes());

    let capped = UpstreamClient::new("http://127.0.0.1:1".into(), Some(4)).expect("client");
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .body(Body::from("12345"))
        .expect("request");
    let resp = capped.forward(req, &signer).await;
    assert_eq!(resp.status().as_u16(), 413);
    assert!(resp.headers().get("content-type").is_none());
    assert!(!resp
        .headers()
        .keys()
        .any(|k| k.as_str().starts_with("vrpc-")));
    let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    assert!(got.is_empty());
}

async fn serve(state: AppState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind router");
    let addr = listener.local_addr().expect("router addr");
    let app = build_router(state, None);
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    format!("http://{addr}")
}

async fn call(
    method: &str,
    url: String,
    accept_encoding: &str,
    body: &'static [u8],
) -> (u16, HeaderMap, Vec<u8>) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = hyper::Request::builder()
        .method(method)
        .uri(url)
        .header("accept-encoding", accept_encoding)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(body)))
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
async fn router_gzips_passthrough_for_gzip_clients_only() {
    let body: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x00000000000000000000000000000000000000000000000000000000000000ff\"}";
    let (url, upstream) = mock(reply(
        "200 OK",
        &[("Content-Type", "application/json")],
        body,
    ))
    .await;
    let signer = signer();
    let base = serve(AppState::for_test(
        UpstreamClient::new(url, None).expect("upstream client"),
        signer.clone(),
    ))
    .await;

    let (status, headers, raw) = call("POST", format!("{base}/"), "gzip", b"{}").await;
    assert_eq!(status, 200);
    assert_eq!(header_str(&headers, "content-encoding"), "gzip");
    assert!(headers
        .get_all("vary")
        .iter()
        .any(|v| v.to_str().is_ok_and(|s| s.contains("accept-encoding"))));
    let mut gunzipped = Vec::new();
    flate2::read::GzDecoder::new(&raw[..])
        .read_to_end(&mut gunzipped)
        .expect("gunzip");
    assert_eq!(gunzipped, body);
    assert_signed(&signer, &headers, b"{}", &gunzipped);

    let (status, headers, raw) = call("POST", format!("{base}/"), "identity", b"{}").await;
    assert_eq!(status, 200);
    assert!(headers.get("content-encoding").is_none());
    assert_eq!(raw, body);
    assert_signed(&signer, &headers, b"{}", &raw);
    assert_eq!(upstream.conns.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn info_route_is_pinned() {
    let base = serve(AppState::for_test(
        UpstreamClient::new("http://127.0.0.1:1".into(), None).expect("upstream client"),
        signer(),
    ))
    .await;
    let (status, headers, body) = call("GET", format!("{base}/info"), "identity", b"").await;
    assert_eq!(status, 200);
    assert_eq!(header_str(&headers, "content-type"), "application/json");
    assert_eq!(body, b"{}");
}
