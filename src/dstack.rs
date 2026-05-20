//! Thin facade over [`dstack-sdk`]. The wrapper exists for a single reason:
//! **per-request timeout.** Each SDK call is wrapped in a 5-second
//! [`tokio::time::timeout`] — the SDK exposes no per-request timeout, and a
//! stuck dstack agent would otherwise hang the sidecar.
//!
//! Socket-path resolution is delegated entirely to the SDK: CLI flag →
//! `DSTACK_SIMULATOR_ENDPOINT` env → probe `/var/run/dstack.sock`,
//! `/run/dstack.sock`, `/var/run/dstack/dstack.sock`, `/run/dstack/dstack.sock`,
//! falling back to the first if none exist.
//!
//! [`GetKeyResponse`], [`GetQuoteResponse`], and [`InfoResponse`] are
//! re-exported from the SDK directly. Two free helpers cover spots where the
//! SDK's surface needs a touch-up:
//! - [`decode_key_hex`] tolerates an optional `0x` prefix (SDK's own
//!   `GetKeyResponse::decode_key` assumes bare hex).
//! - [`compose_hash`] reads the top-level `compose_hash` and falls back to
//!   `tcb_info.compose_hash` if the top-level field is empty (older agents
//!   put it there).
//!
//! The SDK opens a fresh UDS connection per call; on a local UNIX socket the
//! connect cost is microseconds, so we do NOT pool connections here.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::time::timeout;

use dstack_sdk::dstack_client::DstackClient as SdkClient;

// Re-export SDK response types directly — we previously re-declared these
// locally and gained nothing but maintenance burden.
pub use dstack_sdk::dstack_client::{GetKeyResponse, GetQuoteResponse, InfoResponse};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct DstackClient {
    /// SDK client behind `Arc` so `Clone` stays cheap (SDK type itself does
    /// not implement `Clone`; we hand out clones of the `Arc` instead).
    inner: Arc<SdkClient>,
}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        Self {
            inner: Arc::new(SdkClient::new(endpoint)),
        }
    }

    pub async fn get_key(
        &self,
        path: Option<&str>,
        purpose: Option<&str>,
    ) -> Result<GetKeyResponse> {
        let fut = self
            .inner
            .get_key(path.map(str::to_owned), purpose.map(str::to_owned));
        timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack get_key: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack get_key")
    }

    pub async fn get_quote(&self, report_data: &[u8]) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            bail!(
                "report_data must be 1..=64 bytes, got {}",
                report_data.len()
            );
        }
        let fut = self.inner.get_quote(report_data.to_vec());
        timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack get_quote: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack get_quote")
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let fut = self.inner.info();
        timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack info: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack info")
    }
}

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
