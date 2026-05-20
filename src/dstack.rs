//! Free helpers for the dstack-sdk client. The previous local `DstackClient`
//! facade is gone — callers use [`dstack_sdk::dstack_client::DstackClient`]
//! directly. Two helpers remain where the SDK's surface needs a touch-up:
//!
//! - [`decode_key_hex`] tolerates an optional `0x`/`0X` prefix (the SDK's own
//!   `GetKeyResponse::decode_key` assumes bare hex).
//! - [`compose_hash`] reads the top-level `compose_hash` and falls back to
//!   `tcb_info.compose_hash` for older agents that only populated the inner
//!   field.
//!
//! No per-call timeouts: dstack-guest-agent is co-located in the same TDX CVM
//! as the sidecar (DEC-05). A stuck agent means the CVM itself is broken; the
//! sidecar process exiting with it is the correct failure mode.
use anyhow::{Context, Result};
use dstack_sdk::dstack_client::InfoResponse;

/// Hex-decodes a dstack key string, tolerating an optional `0x`/`0X` prefix.
/// The SDK's own `GetKeyResponse::decode_key` assumes bare hex; this helper
/// keeps callers safe against future dstack agents or simulators that emit
/// `0x`-prefixed strings.
pub fn decode_key_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x").trim_start_matches("0X"))
        .context("hex-decode dstack key")
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_key_hex_bare() {
        assert_eq!(
            decode_key_hex("0a1b2c3d").unwrap(),
            vec![0x0a, 0x1b, 0x2c, 0x3d]
        );
    }

    #[test]
    fn decode_key_hex_strips_0x_prefix() {
        assert_eq!(decode_key_hex("0xdead").unwrap(), vec![0xde, 0xad]);
        assert_eq!(decode_key_hex("0XBEEF").unwrap(), vec![0xbe, 0xef]);
    }
}
