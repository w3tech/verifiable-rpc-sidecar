use axum::extract::FromRef;
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

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/attestation", get(attestation_handler))
        .fallback(any(proxy_handler))
        .with_state(state)
}
