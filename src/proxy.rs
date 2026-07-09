// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

// The pipeline helpers return `Result<T, Response>` so each step can
// short-circuit cleanly with `?`. `Response` is ~256 bytes which trips the
// `result_large_err` lint — boxing the error or threading a small ProxyError
// enum would add ceremony for no real benefit; this is intentional.
#![allow(clippy::result_large_err)]

use anyhow::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
    TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use axum::http::{HeaderName, StatusCode, Uri};

/// `Keep-Alive` and `Trailers` (plural) are not in the `http` crate's standard
/// `HeaderName` constant set; create them once at module init so the hop-by-hop
/// check below can do all eight comparisons via `HeaderName::eq` (case-insensitive).
static KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
static TRAILERS: HeaderName = HeaderName::from_static("trailers");
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use tracing::warn;

use crate::server::AppState;
use crate::signing::SigningState;

/// Outbound client speaks both plain HTTP and HTTPS so the sidecar can wrap
/// either a co-located plain-HTTP node or, in local dev, a remote HTTPS
/// upstream. The inbound listener stays plain-HTTP-only — no TLS dependency
/// surfaces on the request-receiving side.
pub type HyperClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone)]
pub struct UpstreamClient {
    client: HyperClient,
    /// Parsed once at construction so request-path code never re-parses on every
    /// call. `Uri` is internally cheap to clone. A malformed URL fails the
    /// constructor → boot aborts with a real error instead of silently 500ing
    /// every request.
    upstream_url: Uri,
    /// Per-request body byte cap applied to both the inbound request body and
    /// the upstream response body. `None` disables the cap — set explicitly by
    /// the operator to allow oversized payloads through.
    max_body_bytes: Option<usize>,
}

impl UpstreamClient {
    /// `upstream_url` is parsed into a `Uri` here; a malformed URL aborts boot
    /// rather than producing silent 500s on every proxied request.
    pub fn new(upstream_url: String, max_body_bytes: Option<usize>) -> anyhow::Result<Self> {
        let upstream_url: Uri = upstream_url
            .parse()
            .with_context(|| format!("invalid upstream URL: {upstream_url:?}"))?;
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            client,
            upstream_url,
            max_body_bytes,
        })
    }

    /// Build the upstream URI: the configured `upstream_url` with the inbound
    /// request's path+query appended. A single trailing `/` on the base is
    /// collapsed against the request path's leading `/`. Empty inbound path → `/`.
    fn upstream_uri(&self, parts: &http::request::Parts) -> Result<Uri, http::Error> {
        let req_pq = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let base = self.upstream_url.to_string();
        format!("{}{}", base.trim_end_matches('/'), req_pq)
            .parse()
            .map_err(Into::into)
    }

    /// Byte-opaque pass-through with per-response signing.
    ///
    /// Pipeline: collect request → build upstream request → send → collect
    /// upstream response → sign → build signed response. Each step short-circuits
    /// with a typed Response on failure via `?`.
    ///
    /// Request body is forwarded verbatim; never parsed. The upstream is forced
    /// to `Accept-Encoding: identity`, so the response body collected here is the
    /// content-decoded (plaintext) JSON the node produced. The response carries
    /// `vRPC-*` headers signing the canonical pre-image over that plaintext body.
    /// Client-facing transport compression is applied later by the router's
    /// `CompressionLayer`, strictly after signing — the client recovers the
    /// signed plaintext by decoding `Content-Encoding`, then verifies.
    pub async fn forward(&self, req: Request, signer: &SigningState) -> Response {
        let cap = self.max_body_bytes.unwrap_or(usize::MAX);
        match self.run_pipeline(req, signer, cap).await {
            Ok(resp) => resp,
            Err(early) => early,
        }
    }

    async fn run_pipeline(
        &self,
        req: Request,
        signer: &SigningState,
        cap: usize,
    ) -> Result<Response, Response> {
        let (parts, request_bytes) = collect_request(req, cap).await?;
        let up_resp = self.send_upstream(parts, request_bytes.clone()).await?;
        let (up_parts, response_bytes) = collect_upstream_response(up_resp, cap).await?;
        let signed = sign_or_500(signer, &request_bytes, &response_bytes)?;
        Ok(build_signed_response(up_parts, response_bytes, signed))
    }

    async fn send_upstream(
        &self,
        parts: http::request::Parts,
        request_bytes: Bytes,
    ) -> Result<hyper::Response<hyper::body::Incoming>, Response> {
        let upstream_uri = self.upstream_uri(&parts).map_err(|err| {
            warn!(error = %err, "failed to build upstream URI");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
        let mut up_builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(upstream_uri);
        for (name, value) in &parts.headers {
            // Skip the client's `Accept-Encoding` entirely; the upstream value is
            // forced to `identity` below so the node returns plaintext and the
            // signed `response_bytes` are content-decoded.
            if !is_hop_by_hop(name) && name != ACCEPT_ENCODING {
                up_builder = up_builder.header(name, value);
            }
        }
        // Force identity on upstream — exactly one `accept-encoding: identity`,
        // replacing (never appending to) any client value. Appending would let
        // the node pick gzip → signature over compressed bytes → broken.
        up_builder = up_builder.header(ACCEPT_ENCODING, "identity");
        let up_req = up_builder
            .body(Full::new(request_bytes))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        self.client.request(up_req).await.map_err(|err| {
            warn!(error = %err, "upstream request failed");
            StatusCode::BAD_GATEWAY.into_response()
        })
    }
}

/// Collect the inbound request body into `Bytes`, enforcing `cap`.
///
/// `axum::Request` consumes its body via `poll_frame`, bypassing
/// `DefaultBodyLimit`, so the explicit `Limited` wrapper here is what actually
/// enforces the cap on the proxy path. `cap = usize::MAX` is the unbounded
/// mode (when `--max-body-bytes` is unset).
async fn collect_request(
    req: Request,
    cap: usize,
) -> Result<(http::request::Parts, Bytes), Response> {
    let (parts, body) = req.into_parts();
    let bytes = Limited::new(body, cap)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|err| {
            warn!(error = %err, "request body rejected (size cap or transport)");
            StatusCode::PAYLOAD_TOO_LARGE.into_response()
        })?;
    Ok((parts, bytes))
}

/// Collect the upstream response body, enforcing the same `cap` as for the
/// inbound path — a malicious or misconfigured upstream returning an unbounded
/// stream would otherwise OOM the sidecar process.
async fn collect_upstream_response(
    up_resp: hyper::Response<hyper::body::Incoming>,
    cap: usize,
) -> Result<(http::response::Parts, Bytes), Response> {
    let (up_parts, up_body) = up_resp.into_parts();
    let bytes = Limited::new(up_body, cap)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|err| {
            warn!(error = %err, "upstream response body exceeded cap or failed");
            StatusCode::BAD_GATEWAY.into_response()
        })?;
    Ok((up_parts, bytes))
}

/// Sign the request/response pair. Refuse to serve if the system clock is
/// unusable — emitting a signed `vRPC-Timestamp: 0` would bypass client-side
/// replay-window enforcement.
fn sign_or_500(
    signer: &SigningState,
    request_bytes: &[u8],
    response_bytes: &[u8],
) -> Result<crate::signing::SignedResponse, Response> {
    signer.sign(request_bytes, response_bytes).map_err(|err| {
        warn!(error = %err, "refusing to sign: clock unusable");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

/// Build the final client-facing response: upstream status + non-hop-by-hop
/// headers + signing headers + body.
fn build_signed_response(
    up_parts: http::response::Parts,
    response_bytes: Bytes,
    signed: crate::signing::SignedResponse,
) -> Response {
    let mut builder = Response::builder().status(up_parts.status);
    for (name, value) in &up_parts.headers {
        // Don't relay a stale/spurious `Content-Encoding` to the client. Upstream
        // is forced to identity so none is expected, but defend explicitly:
        // `CompressionLayer` is the sole owner of the client-facing encoding.
        if !is_hop_by_hop(name) && name != CONTENT_ENCODING {
            builder = builder.header(name, value);
        }
    }
    builder = builder
        .header("vRPC-Signature", signed.signature_hex())
        .header("vRPC-Timestamp", signed.timestamp_ms.to_string())
        .header("vRPC-Pubkey", signed.pubkey_hex());
    builder
        .body(Body::from(response_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub async fn proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    state.upstream.forward(req, &state.signing).await
}

/// RFC 7230 §6.1 hop-by-hop headers — never forwarded across the proxy boundary.
///
/// `HeaderName::eq` does the comparison via interned/normalised forms
/// (already lowercase on the canonical path) but, crucially, also works when a
/// caller hands us a manually-constructed `HeaderName::from_static("Connection")`
/// that bypasses axum's normalisation. A `name.as_str() == "connection"`
/// chain would let any mixed-case header through in that scenario.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == KEEP_ALIVE
        || name == PROXY_AUTHENTICATE
        || name == PROXY_AUTHORIZATION
        || name == TE
        || name == TRAILERS
        || name == TRAILER
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == HOST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_recognised() {
        for h in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",
        ] {
            let name: HeaderName = h.parse().unwrap();
            assert!(is_hop_by_hop(&name), "{h} should be hop-by-hop");
        }
    }

    #[test]
    fn hop_by_hop_check_is_case_insensitive() {
        // `HeaderName::eq` is case-insensitive, so mixed-case spellings
        // that bypass axum's lowercasing (e.g. a manually-constructed `from_static`
        // call elsewhere in the codebase) must still be filtered.
        for h in [
            "Connection",
            "CONNECTION",
            "Keep-Alive",
            "KEEP-ALIVE",
            "Proxy-Authenticate",
            "PROXY-AUTHORIZATION",
            "TE",
            "Trailers",
            "TRAILER",
            "Transfer-Encoding",
            "Upgrade",
            "Host",
        ] {
            let name: HeaderName = h.parse().unwrap();
            assert!(
                is_hop_by_hop(&name),
                "{h} (mixed-case) should be hop-by-hop"
            );
        }
    }

    #[test]
    fn end_to_end_headers_pass_through() {
        for h in [
            "content-type",
            "x-trace-id",
            "vrpc-signature",
            "vrpc-pubkey",
        ] {
            let name: HeaderName = h.parse().unwrap();
            assert!(!is_hop_by_hop(&name), "{h} should be end-to-end");
        }
    }

    #[test]
    fn upstream_client_is_cheap_to_clone() {
        let c = UpstreamClient::new("http://localhost:1/".into(), Some(8 * 1024 * 1024))
            .expect("valid upstream URL");
        let _c2 = c.clone();
    }

    #[test]
    fn upstream_client_rejects_malformed_url_at_construction() {
        let err = match UpstreamClient::new("not a url".into(), Some(8 * 1024 * 1024)) {
            Ok(_) => panic!("expected error for malformed URL"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("invalid upstream URL"),
            "expected upstream URL error, got: {err}"
        );
    }

    /// Asserts the request-side hop-by-hop strip happens at the wire level —
    /// not just on the helper. Spins up an inline `TcpListener` mock upstream,
    /// builds a request with every RFC 7230 §6.1 hop-by-hop header set, calls
    /// `UpstreamClient::forward`, then parses the raw bytes the mock received
    /// and asserts none of those header names made it through. Defends against
    /// a future regression that drops `is_hop_by_hop` filtering inside
    /// `send_upstream`.
    #[tokio::test]
    async fn request_hop_by_hop_headers_stripped_to_upstream() {
        use std::sync::{Arc, Mutex};
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral mock");
        let addr = listener.local_addr().expect("local_addr");
        let upstream_url = format!("http://{addr}/");

        // Accept-once task: read until end of headers, capture bytes, write a
        // minimal 200 OK back so the proxy pipeline can finish, then drop.
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_cl = captured.clone();
        let accept_task = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let mut acc: Vec<u8> = Vec::new();
            loop {
                let n = stream.read(&mut buf).await.expect("read mock");
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                // Headers terminate at `\r\n\r\n`; once we see that, capture
                // and reply. Body bytes after may or may not be present in the
                // same read — irrelevant for header assertions.
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            *captured_cl.lock().unwrap() = acc;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        });

        let client =
            UpstreamClient::new(upstream_url, None).expect("UpstreamClient::new valid URL");
        let signer = SigningState::from_seed([0u8; 32], "1");

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            // Hop-by-hop headers that MUST be stripped at the upstream boundary.
            .header("Transfer-Encoding", "chunked")
            .header("TE", "trailers")
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=5")
            .header("Upgrade", "h2c")
            .header("Proxy-Authorization", "Basic xxx")
            // Client requests compression; the sidecar MUST replace this with a
            // single `accept-encoding: identity` on the upstream leg.
            .header("Accept-Encoding", "gzip, br")
            // End-to-end header that MUST survive the filter.
            .header("X-Trace-Id", "e2e-marker")
            .body(Body::from(b"payload".to_vec()))
            .expect("build request");

        // Pipeline must complete; response is ignored.
        let _ = client.forward(req, &signer).await;

        // Recover the captured upstream-side bytes; defensive timeout in case
        // the accept task hung.
        tokio::time::timeout(Duration::from_secs(5), accept_task)
            .await
            .expect("mock accept task hung")
            .expect("mock accept task panicked");

        let bytes = captured.lock().unwrap().clone();
        let mut header_buf = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut header_buf);
        parsed.parse(&bytes).expect("parse upstream request");

        // Forbidden hop-by-hop names (Host intentionally excluded — hyper
        // rewrites Host to match the upstream URI on send, which is
        // acceptable and tested elsewhere).
        let forbidden = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ];
        for h in &forbidden {
            assert!(
                !parsed
                    .headers
                    .iter()
                    .any(|p| p.name.eq_ignore_ascii_case(h)),
                "hop-by-hop header `{h}` leaked to upstream; got headers: {:?}",
                parsed.headers.iter().map(|p| p.name).collect::<Vec<_>>()
            );
        }

        // x-trace-id must pass through unchanged.
        let trace = parsed
            .headers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("x-trace-id"))
            .expect("x-trace-id absent — over-eager filter regression");
        assert_eq!(
            trace.value, b"e2e-marker",
            "x-trace-id mutated on the upstream path"
        );

        // The client's `Accept-Encoding: gzip, br` must be REPLACED by
        // exactly one `accept-encoding: identity` on the upstream leg — not
        // appended. Appending would let the node pick gzip → response signed
        // over compressed bytes → broken.
        let accept_encodings: Vec<&[u8]> = parsed
            .headers
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case("accept-encoding"))
            .map(|p| p.value)
            .collect();
        assert_eq!(
            accept_encodings.len(),
            1,
            "upstream must receive exactly one accept-encoding header; got {accept_encodings:?}"
        );
        assert_eq!(
            accept_encodings[0], b"identity",
            "upstream accept-encoding must be `identity` (client value replaced, not appended)"
        );
    }

    /// Asserts the transport-failure contract: a connection-refused upstream
    /// (port 1 is privileged and never bound by user services on macOS/Linux)
    /// surfaces as HTTP 502 with NO synthesized JSON-RPC error envelope and
    /// NO hang. Defends against a future regression that fabricates an
    /// `{"jsonrpc":..., "error": ...}` body or drops the 5s liveness guard.
    #[tokio::test]
    async fn upstream_connection_refused_returns_502() {
        use std::time::Duration;

        let client = UpstreamClient::new("http://127.0.0.1:1/".into(), None)
            .expect("UpstreamClient::new valid URL");
        let signer = SigningState::from_seed([0u8; 32], "1");

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(b"hello".to_vec()))
            .expect("build request");

        // 5s timeout guards against a future regression that introduces a hang.
        let response = tokio::time::timeout(Duration::from_secs(5), client.forward(req, &signer))
            .await
            .expect("forward must complete within 5s on connection-refused");

        assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "connection-refused must surface as 502, got {}",
            response.status()
        );

        // Response body must NOT be a synthesized JSON-RPC envelope — empty
        // OR plain bytes are both acceptable; what's forbidden is the sidecar
        // fabricating a `{"jsonrpc":..., "error":{...}}` payload.
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect body");
        let body_str = std::str::from_utf8(&body_bytes).unwrap_or("<binary>");
        assert!(
            body_bytes.is_empty()
                || (!body_str.contains("\"jsonrpc\"") && !body_str.contains("\"error\":{")),
            "502 body must not be a synthesized JSON-RPC envelope; got: {body_str}"
        );
    }

    fn parts_for(uri: &str) -> http::request::Parts {
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .expect("build request")
            .into_parts()
            .0
    }

    /// Core of SHARK-3428: the upstream URI is the configured base plus the
    /// inbound request's path+query. A path-based REST call (TON's
    /// `GET /getConsensusBlock`) against a base origin reaches its endpoint
    /// instead of a single fixed path.
    #[test]
    fn upstream_uri_is_base_plus_request_path_and_query() {
        let client =
            UpstreamClient::new("http://127.0.0.1:43677".into(), None).expect("valid upstream URL");
        let parts = parts_for("/getConsensusBlock?limit=1");
        let uri = client.upstream_uri(&parts).expect("build upstream uri");
        assert_eq!(
            uri.to_string(),
            "http://127.0.0.1:43677/getConsensusBlock?limit=1"
        );
    }

    /// The configured base is used verbatim — a base PATH prefix is preserved
    /// (not trimmed) and the request path is appended after it.
    #[test]
    fn upstream_uri_preserves_configured_base_path() {
        let client = UpstreamClient::new("http://127.0.0.1:43677/api/v2".into(), None)
            .expect("valid upstream URL");
        let parts = parts_for("/getConsensusBlock");
        let uri = client.upstream_uri(&parts).expect("build upstream uri");
        assert_eq!(
            uri.to_string(),
            "http://127.0.0.1:43677/api/v2/getConsensusBlock"
        );
    }

    /// A single trailing slash on the base is not doubled with the request's
    /// leading slash.
    #[test]
    fn upstream_uri_base_trailing_slash_not_doubled() {
        let client = UpstreamClient::new("http://127.0.0.1:43677/api/".into(), None)
            .expect("valid upstream URL");
        let parts = parts_for("/foo");
        let uri = client.upstream_uri(&parts).expect("build upstream uri");
        assert_eq!(uri.to_string(), "http://127.0.0.1:43677/api/foo");
    }

    /// jsonRPC backward-compat: a client `POST /jsonRPC` against a base origin
    /// resolves to `<base>/jsonRPC` — existing EVM/TON jsonRPC vRPC nodes
    /// behave identically after the change (their config must be the base origin).
    #[test]
    fn upstream_uri_preserves_jsonrpc_path() {
        let client =
            UpstreamClient::new("http://127.0.0.1:8545".into(), None).expect("valid upstream URL");
        let parts = parts_for("/jsonRPC");
        let uri = client.upstream_uri(&parts).expect("build upstream uri");
        assert_eq!(uri.to_string(), "http://127.0.0.1:8545/jsonRPC");
    }

    /// Root path forwarded as-is (EVM jsonRPC-at-root via shark's RPC path posts to `/`).
    #[test]
    fn upstream_uri_forwards_root_path() {
        let client =
            UpstreamClient::new("http://127.0.0.1:8545".into(), None).expect("valid upstream URL");
        let parts = parts_for("/");
        let uri = client.upstream_uri(&parts).expect("build upstream uri");
        assert_eq!(uri.to_string(), "http://127.0.0.1:8545/");
    }
}
