use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get};
use axum::Router;

use dstack_sdk::dstack_client::DstackClient;

use crate::attestation::{attestation_handler, AttestationState};
use crate::info::info_handler;
use crate::proxy::{proxy_handler, UpstreamClient};
use crate::signing::SigningState;

#[derive(Clone)]
pub struct AppState {
    pub upstream: UpstreamClient,
    pub signing: SigningState,
    pub attestation: AttestationState,
    pub dstack: Arc<DstackClient>,
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
        .with_state(state)
}
