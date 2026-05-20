//! Free helpers for the dstack-sdk client. The previous local `DstackClient`
//! facade is gone — callers use [`dstack_sdk::dstack_client::DstackClient`]
//! directly. Hex-decoding of `GetKeyResponse.key` is done via the SDK's own
//! `GetKeyResponse::decode_key` method.
//!
//! What remains here: [`compose_hash`] — top-level `compose_hash` first,
//! fallback to `tcb_info.compose_hash` for older agents that only populated
//! the inner field.
//!
//! No per-call timeouts: dstack-guest-agent is co-located in the same TDX CVM
//! as the sidecar (DEC-05). A stuck agent means the CVM itself is broken; the
//! sidecar process exiting with it is the correct failure mode.
use dstack_sdk::dstack_client::InfoResponse;

/// Resolve the compose hash from an [`InfoResponse`]. Prefers the top-level
/// `compose_hash` field; falls back to `tcb_info.compose_hash` for older
/// dstack-guest-agent versions that only populated the inner field.
/// Returns `None` if both are empty.
pub fn compose_hash(info: &InfoResponse) -> Option<String> {
    if !info.compose_hash.is_empty() {
        return Some(info.compose_hash.clone());
    }
    if !info.tcb_info.compose_hash.is_empty() {
        return Some(info.tcb_info.compose_hash.clone());
    }
    None
}
