use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use tracing::warn;

pub type HyperClient = Client<HttpConnector, Full<Bytes>>;

#[derive(Clone)]
pub struct UpstreamClient {
    client: HyperClient,
    upstream_url: Arc<String>,
}

impl UpstreamClient {
    pub fn new(upstream_url: String) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            client,
            upstream_url: Arc::new(upstream_url),
        }
    }

    /// Best-effort upstream reachability probe used by `/readyz`. Any HTTP response
    /// counts as reachable — only transport errors flip the verdict.
    pub async fn is_reachable(&self) -> bool {
        let Ok(uri) = self.upstream_url.parse::<Uri>() else {
            return false;
        };
        let Ok(req) = hyper::Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Full::new(Bytes::new()))
        else {
            return false;
        };
        self.client.request(req).await.is_ok()
    }

    /// Byte-opaque pass-through. Forwards request body bytes verbatim to upstream
    /// and returns the response body bytes verbatim — no JSON parsing, no mutation.
    /// Hop-by-hop headers are stripped in both directions.
    pub async fn forward(&self, req: Request) -> Response {
        let (parts, body) = req.into_parts();

        let body_bytes = match body.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };

        let upstream_uri: Uri = match self.upstream_url.parse() {
            Ok(u) => u,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        let mut up_builder = hyper::Request::builder()
            .method(parts.method.clone())
            .uri(upstream_uri);
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name) {
                up_builder = up_builder.header(name, value);
            }
        }
        let up_req = match up_builder.body(Full::new(body_bytes)) {
            Ok(r) => r,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        match self.client.request(up_req).await {
            Ok(up_resp) => {
                let (up_parts, up_body) = up_resp.into_parts();
                let resp_bytes = match up_body.collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
                };
                let mut builder = Response::builder().status(up_parts.status);
                for (name, value) in &up_parts.headers {
                    if !is_hop_by_hop(name) {
                        builder = builder.header(name, value);
                    }
                }
                builder
                    .body(Body::from(resp_bytes))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            Err(err) => {
                warn!(error = %err, "upstream request failed");
                StatusCode::BAD_GATEWAY.into_response()
            }
        }
    }
}

pub async fn proxy_handler(State(client): State<UpstreamClient>, req: Request) -> Response {
    client.forward(req).await
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
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
    fn end_to_end_headers_pass_through() {
        for h in [
            "content-type",
            "x-trace-id",
            "x-phala-signature",
            "x-phala-pubkey",
        ] {
            let name: HeaderName = h.parse().unwrap();
            assert!(!is_hop_by_hop(&name), "{h} should be end-to-end");
        }
    }

    #[test]
    fn upstream_client_is_cheap_to_clone() {
        let c = UpstreamClient::new("http://localhost:1/".into());
        let _c2 = c.clone();
    }
}
