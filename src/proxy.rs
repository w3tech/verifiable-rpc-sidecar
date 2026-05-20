// The pipeline helpers return `Result<T, Response>` so each step can
// short-circuit cleanly with `?`. `Response` is ~256 bytes which trips the
// `result_large_err` lint — boxing the error or threading a small ProxyError
// enum would add ceremony for no real benefit; this is intentional.
#![allow(clippy::result_large_err)]

use anyhow::Context;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{
    CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
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

    /// Byte-opaque pass-through with per-response signing.
    ///
    /// Pipeline: collect request → build upstream request → send → collect
    /// upstream response → sign → build signed response. Each step short-circuits
    /// with a typed Response on failure via `?`.
    ///
    /// Bodies are forwarded verbatim in both directions — never parsed, never
    /// mutated. The response carries `vRPC-*` headers signing the canonical
    /// pre-image over the response body bytes returned by upstream (signed
    /// post-serialisation, so the signature covers exactly the bytes the
    /// client receives).
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
        let mut up_builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(self.upstream_url.clone());
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name) {
                up_builder = up_builder.header(name, value);
            }
        }
        let up_req = up_builder
            .body(Full::new(request_bytes))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
        self.client.request(up_req).await.map_err(|err| {
            warn!(error = %err, "upstream request failed");
            StatusCode::BAD_GATEWAY.into_response()
        })
    }
}

/// Collect a body into `Bytes`, enforcing `cap`. On error, emits a warn-level
/// log with `err_msg` and returns a typed `Response` with `err_status`.
///
/// `axum::Request` consumes its body via `poll_frame`, bypassing
/// `DefaultBodyLimit`, so the explicit `Limited` wrapper here is what actually
/// enforces the cap on the proxy path. `cap = usize::MAX` is the unbounded mode
/// (when `--max-body-bytes` is unset).
async fn collect_body<B>(
    body: B,
    cap: usize,
    err_status: StatusCode,
    err_msg: &'static str,
) -> Result<Bytes, Response>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Limited::new(body, cap)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|err| {
            warn!(error = %err, "{err_msg}");
            err_status.into_response()
        })
}

/// Destructure the inbound request and collect its body via `collect_body`.
async fn collect_request(
    req: Request,
    cap: usize,
) -> Result<(http::request::Parts, Bytes), Response> {
    let (parts, body) = req.into_parts();
    let bytes = collect_body(
        body,
        cap,
        StatusCode::PAYLOAD_TOO_LARGE,
        "request body rejected (size cap or transport)",
    )
    .await?;
    Ok((parts, bytes))
}

/// Destructure the upstream response and collect its body. The cap is the same
/// as for the inbound path — a malicious or misconfigured upstream returning an
/// unbounded stream would otherwise OOM the sidecar process.
async fn collect_upstream_response(
    up_resp: hyper::Response<hyper::body::Incoming>,
    cap: usize,
) -> Result<(http::response::Parts, Bytes), Response> {
    let (up_parts, up_body) = up_resp.into_parts();
    let bytes = collect_body(
        up_body,
        cap,
        StatusCode::BAD_GATEWAY,
        "upstream response body exceeded cap or failed",
    )
    .await?;
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
        if !is_hop_by_hop(name) {
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
}
