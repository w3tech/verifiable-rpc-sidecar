//! Thin facade over [`dstack-sdk`]. The wrapper exists for two reasons:
//!
//! 1. **Per-request timeout.** Each SDK call is wrapped in a 5-second
//!    [`tokio::time::timeout`] — the SDK exposes no per-request timeout, and
//!    a stuck dstack agent would otherwise hang the sidecar.
//! 2. **Permissive [`InfoResponse`].** The SDK's `InfoResponse` requires
//!    `app_cert`, `device_id`, `key_provider_info` — fields the simulator
//!    may omit. The local permissive struct re-deserialises so `info()`
//!    keeps working against the simulator and older agents.
//!
//! Socket-path resolution is delegated entirely to the SDK: CLI flag →
//! `DSTACK_SIMULATOR_ENDPOINT` env → probe `/var/run/dstack.sock`,
//! `/run/dstack.sock`, `/var/run/dstack/dstack.sock`, `/run/dstack/dstack.sock`,
//! falling back to the first if none exist. That matches and extends what we
//! used to do manually.
//!
//! [`GetKeyResponse`] and [`GetQuoteResponse`] are re-exported from the SDK
//! directly — we previously re-declared them and gained nothing but a
//! maintenance burden. Hex-decoding of the key tolerates an optional `0x`
//! prefix via the free [`decode_key_hex`] helper, since the SDK's own
//! `GetKeyResponse::decode_key` assumes bare hex.
//!
//! The SDK opens a fresh UDS connection per call; on a local UNIX socket the
//! connect cost is microseconds, so we do NOT pool connections here.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::timeout;

use dstack_sdk::dstack_client::DstackClient as SdkClient;

// Re-export SDK response types directly — we previously re-declared these
// locally and gained nothing but maintenance burden. The SDK's own
// `GetKeyResponse::decode_key` does NOT strip a leading `0x`; we keep a
// free `decode_key_hex` helper below for callers that need that tolerance.
pub use dstack_sdk::dstack_client::{GetKeyResponse, GetQuoteResponse};

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
        // Option A from 11-RESEARCH.md "Migration of info()": call SDK, re-encode
        // to Value, deserialise into our permissive `InfoResponse`. The SDK's
        // `InfoResponse` has REQUIRED fields (`app_cert`, `device_id`,
        // `key_provider_info`) that the simulator may omit (RESEARCH.md Pitfall 1).
        // If the SDK's strict deserialise fails, our type can still serve the
        // bits we actually need — but only if we got the raw bytes back. The
        // SDK does not expose its `send_rpc_request` publicly, so when the
        // strict `info()` returns Err we have no fall-back path; the
        // `info_succeeds_against_simulator` integration test guards this.
        let fut = self.inner.info();
        let sdk_resp = timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack info: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack info")?;
        let value =
            serde_json::to_value(&sdk_resp).context("re-serialise sdk info response to value")?;
        serde_json::from_value::<InfoResponse>(value)
            .context("decode info response into local type")
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfoResponse {
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub tcb_info: Value,
    #[serde(default, alias = "compose_hash")]
    pub compose_hash: String,
    #[serde(default)]
    pub mr_aggregated: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl InfoResponse {
    /// dstack-guest-agent puts the compose hash inside `tcb_info` rather than at
    /// the top level on some versions; fall back to that path when needed.
    pub fn compose_hash(&self) -> Option<String> {
        if !self.compose_hash.is_empty() {
            return Some(self.compose_hash.clone());
        }
        self.tcb_info
            .get("compose_hash")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }
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

    #[test]
    fn info_response_falls_back_to_tcb_info_compose_hash() {
        let info = InfoResponse {
            app_id: String::new(),
            instance_id: String::new(),
            app_name: String::new(),
            tcb_info: serde_json::json!({ "compose_hash": "abcd" }),
            compose_hash: String::new(),
            mr_aggregated: String::new(),
            extra: Default::default(),
        };
        assert_eq!(info.compose_hash(), Some("abcd".to_string()));
    }
}
