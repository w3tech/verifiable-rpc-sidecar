//! Thin facade over [`dstack-sdk`] that preserves a stable local public API
//! so callers in `main.rs` and `attestation.rs` are insulated from SDK churn.
//!
//! The facade owns response types (`GetKeyResponse`, `GetQuoteResponse`,
//! `InfoResponse`) locally and translates from the SDK's types at the boundary.
//! Each call is wrapped with a 5-second [`tokio::time::timeout`] — the SDK
//! exposes no per-request timeout. The SDK opens a fresh UDS connection per
//! call; on a local UNIX socket the connect cost is microseconds, so we do
//! NOT pool connections at the facade layer.
//!
//! Default socket path matches the agent default of `/var/run/dstack.sock`;
//! override via `DSTACK_SIMULATOR_ENDPOINT` for the
//! [Phala dstack local simulator](https://docs.phala.com/dstack/local-development).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::timeout;

use dstack_sdk::dstack_client::DstackClient as SdkClient;

const DEFAULT_SOCKET: &str = "/var/run/dstack.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct DstackClient {
    socket: PathBuf,
    /// SDK client behind `Arc` so `Clone` stays cheap (SDK type itself does
    /// not implement `Clone`; we hand out clones of the `Arc` instead).
    inner: Arc<SdkClient>,
}

impl std::fmt::Debug for DstackClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DstackClient")
            .field("socket", &self.socket)
            .finish()
    }
}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        // 3-tier socket-path resolution mirrors the pre-migration behaviour:
        // CLI flag → `DSTACK_SIMULATOR_ENDPOINT` env → `/var/run/dstack.sock`.
        // We resolve FIRST and pass the resolved string to the SDK so the
        // SDK's own env-fallback + multi-path probe never observes a `None`.
        let socket = match endpoint {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => match std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok() {
                Some(p) if !p.is_empty() => PathBuf::from(p),
                _ => PathBuf::from(DEFAULT_SOCKET),
            },
        };
        let inner = Arc::new(SdkClient::new(Some(socket.to_string_lossy().as_ref())));
        Self { socket, inner }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub async fn get_key(
        &self,
        path: Option<&str>,
        purpose: Option<&str>,
    ) -> Result<GetKeyResponse> {
        let fut = self
            .inner
            .get_key(path.map(str::to_owned), purpose.map(str::to_owned));
        let sdk_resp = timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack get_key: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack get_key")?;
        Ok(GetKeyResponse {
            key: sdk_resp.key,
            signature_chain: sdk_resp.signature_chain,
        })
    }

    pub async fn get_quote(&self, report_data: &[u8]) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            bail!(
                "report_data must be 1..=64 bytes, got {}",
                report_data.len()
            );
        }
        let fut = self.inner.get_quote(report_data.to_vec());
        let sdk_resp = timeout(REQUEST_TIMEOUT, fut)
            .await
            .with_context(|| format!("dstack get_quote: timed out after {REQUEST_TIMEOUT:?}"))?
            .context("dstack get_quote")?;
        Ok(GetQuoteResponse {
            quote: sdk_resp.quote,
            event_log: sdk_resp.event_log,
            report_data: sdk_resp.report_data,
            vm_config: sdk_resp.vm_config,
        })
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetKeyResponse {
    /// Hex-encoded private key bytes.
    pub key: String,
    /// Signature chain (hex strings) — opaque to v2; surfaced for v3 attestation tooling.
    #[serde(default)]
    pub signature_chain: Vec<String>,
}

impl GetKeyResponse {
    /// Hex-decodes `self.key`, tolerating an optional `0x` prefix. The SDK's
    /// own `decode_key` does NOT strip the prefix; ours does and
    /// `src/signing.rs::SigningState::from_dstack_bytes` depends on the
    /// stripped bytes.
    pub fn decode_key(&self) -> Result<Vec<u8>> {
        hex::decode(self.key.trim_start_matches("0x")).context("hex-decode dstack key")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetQuoteResponse {
    /// Hex-encoded TDX quote bytes.
    pub quote: String,
    /// Hex-encoded RTMR event log.
    #[serde(default)]
    pub event_log: String,
    #[serde(default)]
    pub report_data: String,
    #[serde(default)]
    pub vm_config: String,
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
    fn client_uses_explicit_endpoint() {
        let c = DstackClient::new(Some("/tmp/fake.sock"));
        assert_eq!(c.socket_path(), Path::new("/tmp/fake.sock"));
    }

    #[test]
    fn client_falls_back_to_default_when_no_endpoint() {
        // Save and clear env, then restore.
        let prev = std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok();
        std::env::remove_var("DSTACK_SIMULATOR_ENDPOINT");
        let c = DstackClient::new(None);
        assert_eq!(c.socket_path(), Path::new(DEFAULT_SOCKET));
        if let Some(v) = prev {
            std::env::set_var("DSTACK_SIMULATOR_ENDPOINT", v);
        }
    }

    #[test]
    fn get_key_response_decodes_key_bytes() {
        let r = GetKeyResponse {
            key: "0a1b2c3d".into(),
            signature_chain: vec![],
        };
        assert_eq!(r.decode_key().unwrap(), vec![0x0a, 0x1b, 0x2c, 0x3d]);
    }

    #[test]
    fn get_key_response_tolerates_0x_prefix() {
        let r = GetKeyResponse {
            key: "0xdead".into(),
            signature_chain: vec![],
        };
        assert_eq!(r.decode_key().unwrap(), vec![0xde, 0xad]);
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
