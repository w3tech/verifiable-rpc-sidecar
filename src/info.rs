// `GET /info` returns the full `dstack.info()` response as JSON. Testing /
// verification convenience: exposes the deployed `app_compose` text so callers
// can recompute `sha256(canonical(app_compose))` and compare against the
// `composeHash` field served by `/attestation`. No auth, no caching.
//
// Security: this endpoint reveals the deployment config verbatim, including
// any env vars baked into `app_compose.docker_compose_file`. See `AGENTS.md`
// for the hardening backlog.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use dstack_sdk::dstack_client::InfoResponse;

use crate::server::AppState;

/// Handler for `GET /info`. Returns the full `InfoResponse` as JSON or a 502
/// with anyhow context on dstack failure. Mirrors the error shape of
/// `attestation_handler`.
pub async fn info_handler(
    State(state): State<AppState>,
) -> Result<Json<InfoResponse>, (StatusCode, String)> {
    state
        .dstack
        .info()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("dstack info: {e}")))
}
