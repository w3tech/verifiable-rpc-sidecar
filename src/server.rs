use axum::extract::{DefaultBodyLimit, FromRef};
use axum::routing::{any, get};
use axum::Router;

use crate::attestation::{attestation_handler, AttestationState};
use crate::health::{healthz, readyz};
use crate::proxy::{proxy_handler, UpstreamClient};
use crate::signing::SigningState;

#[derive(Clone)]
pub struct AppState {
    pub upstream: UpstreamClient,
    pub signing: SigningState,
    pub attestation: AttestationState,
}

impl FromRef<AppState> for UpstreamClient {
    fn from_ref(state: &AppState) -> Self {
        state.upstream.clone()
    }
}

impl FromRef<AppState> for SigningState {
    fn from_ref(state: &AppState) -> Self {
        state.signing.clone()
    }
}

impl FromRef<AppState> for AttestationState {
    fn from_ref(state: &AppState) -> Self {
        state.attestation.clone()
    }
}

/// Build the router with a request-body size cap (WR-02). `max_body_bytes`
/// applies to every route; per-route extractors that need a larger limit
/// would override it with `DefaultBodyLimit::disable()` (none currently do).
/// The `proxy_handler` enforces the same cap on the upstream response body
/// via `http_body_util::Limited`.
pub fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/attestation", get(attestation_handler))
        .fallback(any(proxy_handler))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}
