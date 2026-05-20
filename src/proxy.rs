use anyhow::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
};
use axum::http::{HeaderName, Method, StatusCode, Uri};

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
    /// Optional `(header_name, header_value)` attached to the `/readyz` probe
    /// so it can pass auth gates on the upstream.
    readyz_auth_header: Option<(HeaderName, http::HeaderValue)>,
}

/// JSON-RPC payload used by the `/readyz` probe — any EVM JSON-RPC upstream
/// answers `web3_clientVersion` cheaply, and answers it with `200 OK`. Any
/// non-2xx response from this probe is a real signal that the upstream is
/// unhealthy.
const READYZ_PROBE_BODY: &[u8] = br#"{"jsonrpc":"2.0","method":"web3_clientVersion","id":0}"#;

impl UpstreamClient {
    pub fn new(upstream_url: String, max_body_bytes: Option<usize>) -> anyhow::Result<Self> {
        Self::with_readyz_auth(upstream_url, max_body_bytes, None)
    }

    /// Build an upstream client with an optional `/readyz`-probe auth header.
    /// `readyz_auth_header` is the raw `"Name: Value"` string from the CLI flag;
    /// any malformed value is logged and dropped (the probe falls back to an
    /// unauthenticated POST) — boot continues either way to keep operator
    /// misconfiguration from crash-looping the pod.
    ///
    /// `upstream_url` is parsed into a `Uri` here; a malformed URL aborts boot
    /// rather than producing silent 500s on every proxied request.
    pub fn with_readyz_auth(
        upstream_url: String,
        max_body_bytes: Option<usize>,
        readyz_auth_header: Option<&str>,
    ) -> anyhow::Result<Self> {
        let upstream_url: Uri = upstream_url
            .parse()
            .with_context(|| format!("invalid upstream URL: {upstream_url:?}"))?;
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(https);
        let readyz_auth_header = readyz_auth_header.and_then(|raw| match parse_header_kv(raw) {
            Ok(pair) => Some(pair),
            Err(err) => {
                warn!(
                    error = %err,
                    raw = %mask_secret(raw),
                    "ignoring --readyz-upstream-auth-header (malformed)"
                );
                None
            }
        });
        Ok(Self {
            client,
            upstream_url,
            max_body_bytes,
            readyz_auth_header,
        })
    }

    /// Active upstream reachability probe used by `/readyz`. POSTs
    /// `web3_clientVersion` and returns true only on a 2xx response — every
    /// healthy EVM JSON-RPC server answers this cheaply, so a 4xx/5xx is a
    /// real signal that the upstream is wedged (auth misconfigured, upstream
    /// down, etc.) rather than a passive "TCP socket open" probe.
    pub async fn is_reachable(&self) -> bool {
        let mut builder = hyper::Request::builder()
            .method(Method::POST)
            .uri(self.upstream_url.clone())
            .header("content-type", "application/json");
        if let Some((name, value)) = &self.readyz_auth_header {
            builder = builder.header(name, value);
        }
        let Ok(req) = builder.body(Full::new(Bytes::from_static(READYZ_PROBE_BODY))) else {
            return false;
        };
        match self.client.request(req).await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Byte-opaque pass-through with optional per-response signing.
    ///
    /// Bodies are forwarded verbatim in both directions — never parsed, never
    /// mutated. When `signer` is provided, the response carries `vRPC-*` headers
    /// signing the canonical pre-image over the response body bytes returned by
    /// upstream (signed post-serialisation, so the signature covers exactly the
    /// bytes the client receives).
    pub async fn forward(&self, req: Request, signer: Option<&SigningState>) -> Response {
        let (parts, body) = req.into_parts();

        // Cap the request body before buffering. `axum::Request` consumes
        // the body via `poll_frame`, bypassing `DefaultBodyLimit`, so the
        // explicit `Limited` wrapper here is what actually enforces the cap on
        // the proxy path. `None` → `usize::MAX` (effectively unbounded).
        let cap = self.max_body_bytes.unwrap_or(usize::MAX);
        let request_bytes = match Limited::new(body, cap).collect().await {
            Ok(c) => c.to_bytes(),
            Err(err) => {
                warn!(error = %err, "request body rejected (size cap or transport)");
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
        };

        let mut up_builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(self.upstream_url.clone());
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name) {
                up_builder = up_builder.header(name, value);
            }
        }
        let up_req = match up_builder.body(Full::new(request_bytes.clone())) {
            Ok(r) => r,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        match self.client.request(up_req).await {
            Ok(up_resp) => {
                let (up_parts, up_body) = up_resp.into_parts();
                // Cap the upstream response body identically. A malicious
                // or misconfigured upstream returning an unbounded stream would
                // otherwise OOM the sidecar process — set `--max-body-bytes`
                // (or `SIDECAR_MAX_BODY_BYTES`) to re-enable the cap.
                let response_bytes = match Limited::new(up_body, cap).collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(err) => {
                        warn!(error = %err, "upstream response body exceeded cap or failed");
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                };

                let mut builder = Response::builder().status(up_parts.status);
                for (name, value) in &up_parts.headers {
                    if !is_hop_by_hop(name) {
                        builder = builder.header(name, value);
                    }
                }
                if let Some(signer) = signer {
                    // Refuse to serve if the system clock is unusable.
                    // Emitting a signed `vRPC-Timestamp: 0` would bypass
                    // client-side replay-window enforcement.
                    let signed = match signer.sign(&request_bytes, &response_bytes) {
                        Ok(s) => s,
                        Err(err) => {
                            warn!(error = %err, "refusing to sign: clock unusable");
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };
                    builder = builder
                        .header("vRPC-Signature", signed.signature_hex())
                        .header("vRPC-Timestamp", signed.timestamp_ms.to_string())
                        .header("vRPC-Pubkey", &signed.pubkey_hex);
                }
                builder
                    .body(Body::from(response_bytes))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            Err(err) => {
                warn!(error = %err, "upstream request failed");
                StatusCode::BAD_GATEWAY.into_response()
            }
        }
    }
}

pub async fn proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    state.upstream.forward(req, Some(&state.signing)).await
}

/// Parse `"Header-Name: header-value"` into a `(HeaderName, HeaderValue)` pair.
/// Used to attach the operator-supplied auth header to the `/readyz` probe.
pub fn parse_header_kv(raw: &str) -> anyhow::Result<(HeaderName, http::HeaderValue)> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected `Name: Value`, got {:?}", mask_secret(raw)))?;
    let name = HeaderName::try_from(name.trim())
        .map_err(|e| anyhow::anyhow!("invalid header name: {e}"))?;
    let value = http::HeaderValue::try_from(value.trim())
        .map_err(|e| anyhow::anyhow!("invalid header value: {e}"))?;
    Ok((name, value))
}

/// Render only the header name from a `Name: Value` string so we never log
/// the value (it's typically a secret).
fn mask_secret(raw: &str) -> String {
    match raw.split_once(':') {
        Some((name, _)) => format!("{}: <redacted>", name.trim()),
        None => "<malformed>".into(),
    }
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

    #[test]
    fn parse_header_kv_round_trips_name_and_value() {
        let (n, v) = parse_header_kv("x-api-key: deadbeef").expect("valid header");
        assert_eq!(n.as_str(), "x-api-key");
        assert_eq!(v.to_str().unwrap(), "deadbeef");
    }

    #[test]
    fn parse_header_kv_tolerates_extra_whitespace() {
        let (n, v) = parse_header_kv("  Authorization :  Bearer xyz  ").expect("valid header");
        assert_eq!(n.as_str(), "authorization");
        assert_eq!(v.to_str().unwrap(), "Bearer xyz");
    }

    #[test]
    fn parse_header_kv_rejects_missing_colon() {
        assert!(parse_header_kv("no-colon-here").is_err());
    }

    #[test]
    fn mask_secret_redacts_value_but_keeps_name() {
        assert_eq!(mask_secret("x-api-key: shh"), "x-api-key: <redacted>");
        assert_eq!(mask_secret("no-colon"), "<malformed>");
    }
}
