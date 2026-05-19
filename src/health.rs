use axum::extract::State;
use axum::http::StatusCode;

use crate::proxy::UpstreamClient;

pub async fn healthz() -> StatusCode {
    StatusCode::OK
}

pub async fn readyz(State(upstream): State<UpstreamClient>) -> StatusCode {
    if upstream.is_reachable().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
