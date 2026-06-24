// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get};
use axum::Router;
use tower_http::compression::CompressionLayer;

use crate::attestation::{attestation_handler, info_handler, AttestationState};
use crate::proxy::{proxy_handler, UpstreamClient};
use crate::signing::SigningState;

#[derive(Clone)]
pub struct AppState {
    pub upstream: UpstreamClient,
    pub signing: SigningState,
    pub attestation: AttestationState,
}

/// Build the router with an optional request-body size cap.
///
/// - `Some(n)` → `DefaultBodyLimit::max(n)` applies to every route.
/// - `None`    → `DefaultBodyLimit::disable()` — unbounded; relies on the
///   upstream's own limits and the CVM's memory budget.
///
/// The `proxy_handler` mirrors the same Option on the upstream response body
/// via `http_body_util::Limited`.
pub fn build_router(state: AppState, max_body_bytes: Option<usize>) -> Router {
    let body_limit = match max_body_bytes {
        Some(n) => DefaultBodyLimit::max(n),
        None => DefaultBodyLimit::disable(),
    };
    Router::new()
        .route("/attestation", get(attestation_handler))
        .route("/info", get(info_handler))
        .fallback(any(proxy_handler))
        .layer(body_limit)
        // Outermost response layer: re-encodes the response body per the CLIENT's
        // Accept-Encoding (gzip + identity) and sets Content-Encoding. Runs strictly
        // AFTER the handler has signed the plaintext body, so it only changes
        // transport encoding and never mutates the signed bytes or `vRPC-*`
        // headers (ENC-03, DEC-D, T-26-02 layer ordering).
        .layer(CompressionLayer::new())
        .with_state(state)
}
