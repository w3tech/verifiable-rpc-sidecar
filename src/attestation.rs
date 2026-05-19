//! `/attestation` endpoint — caches the TDX quote and the surrounding
//! identity fields (`pubkey`, `composeHash`, `eventLog`) so clients can
//! verify the chain `Intel PCK → quote → signing_pubkey` end-to-end.
//!
//! The quote is requested once at startup with
//! `REPORTDATA = signing_pubkey (32B) || user_nonce (32B)` per SPEC-05
//! (closes C3). The cached payload is returned verbatim from every
//! `GET /attestation` until the process restarts (which is the only path
//! to key rotation per SPEC-06).
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::dstack::DstackClient;
use crate::server::AppState;

pub const REPORT_DATA_LEN: usize = 64;
pub const REPORT_DATA_PUBKEY_OFFSET: usize = 0;
pub const REPORT_DATA_NONCE_OFFSET: usize = 32;

/// Cached attestation payload — shared via `Arc` so handler dispatch is
/// allocation-free and the bytes never need to be cloned per request.
#[derive(Clone)]
pub struct AttestationState {
    inner: Arc<AttestationResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationResponse {
    /// TDX quote, hex-encoded, `0x`-prefixed.
    pub quote: String,
    /// RTMR event log, hex-encoded, `0x`-prefixed. Empty if dstack omitted it.
    #[serde(rename = "eventLog")]
    pub event_log: String,
    /// Sidecar signing pubkey (32 raw bytes), hex-encoded, `0x`-prefixed.
    pub pubkey: String,
    /// `app-compose.json` content hash from `dstack info`. Empty if unset by
    /// the simulator.
    #[serde(rename = "composeHash")]
    pub compose_hash: String,
}

impl AttestationState {
    pub async fn bootstrap(
        dstack: &DstackClient,
        signing_pubkey: [u8; 32],
        user_nonce: [u8; 32],
    ) -> Result<Self> {
        let report_data = build_report_data(signing_pubkey, user_nonce);
        let quote = dstack
            .get_quote(&report_data)
            .await
            .context("dstack get_quote")?;
        let info = dstack.info().await.context("dstack info")?;
        let response = AttestationResponse {
            quote: ensure_0x_prefix(&quote.quote),
            event_log: ensure_0x_prefix(&quote.event_log),
            pubkey: ensure_0x_prefix(&hex::encode(signing_pubkey)),
            compose_hash: info.compose_hash().unwrap_or_default(),
        };
        Ok(Self {
            inner: Arc::new(response),
        })
    }

    pub fn from_response(response: AttestationResponse) -> Self {
        Self {
            inner: Arc::new(response),
        }
    }

    pub fn response(&self) -> Arc<AttestationResponse> {
        self.inner.clone()
    }
}

/// Build the SPEC-05 REPORTDATA: 32B signing pubkey concatenated with 32B
/// caller-supplied nonce. Closes C3 — the pubkey is bound into the quote.
pub fn build_report_data(signing_pubkey: [u8; 32], user_nonce: [u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[REPORT_DATA_PUBKEY_OFFSET..REPORT_DATA_NONCE_OFFSET].copy_from_slice(&signing_pubkey);
    out[REPORT_DATA_NONCE_OFFSET..REPORT_DATA_LEN].copy_from_slice(&user_nonce);
    out
}

pub async fn attestation_handler(State(state): State<AppState>) -> Json<AttestationResponse> {
    Json((*state.attestation.response()).clone())
}

fn ensure_0x_prefix(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{s}")
    }
}

/// Parse a hex-encoded 32-byte user nonce (with or without `0x` prefix).
pub fn parse_user_nonce(s: &str) -> Result<[u8; 32]> {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let bytes = hex::decode(trimmed).context("user_nonce must be hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("user_nonce must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_layout_is_64_bytes_pubkey_nonce() {
        let pubkey: [u8; 32] = [0xaa; 32];
        let nonce: [u8; 32] = [0xbb; 32];
        let data = build_report_data(pubkey, nonce);
        assert_eq!(data.len(), 64);
        assert!(data[..32].iter().all(|&b| b == 0xaa));
        assert!(data[32..].iter().all(|&b| b == 0xbb));
    }

    #[test]
    fn report_data_uses_caller_nonce_unmodified() {
        let pubkey: [u8; 32] = [0; 32];
        let nonce: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, //
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, //
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let data = build_report_data(pubkey, nonce);
        assert_eq!(&data[32..], &nonce);
    }

    #[test]
    fn attestation_response_uses_camelcase_keys() {
        let r = AttestationResponse {
            quote: "0xdead".into(),
            event_log: "0xbeef".into(),
            pubkey: "0xabcd".into(),
            compose_hash: "0xfeed".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"eventLog\":\"0xbeef\""));
        assert!(s.contains("\"composeHash\":\"0xfeed\""));
        assert!(s.contains("\"quote\":\"0xdead\""));
        assert!(s.contains("\"pubkey\":\"0xabcd\""));
        // snake_case keys must not leak in:
        assert!(!s.contains("event_log"));
        assert!(!s.contains("compose_hash"));
    }

    #[test]
    fn ensure_0x_prefix_does_not_double_prefix() {
        assert_eq!(ensure_0x_prefix("0xabc"), "0xabc");
        assert_eq!(ensure_0x_prefix("abc"), "0xabc");
        assert_eq!(ensure_0x_prefix(""), "");
        assert_eq!(ensure_0x_prefix("0Xabc"), "0Xabc");
    }

    #[test]
    fn parse_user_nonce_accepts_with_or_without_prefix() {
        let hex = "00".repeat(32);
        let a = parse_user_nonce(&hex).unwrap();
        let b = parse_user_nonce(&format!("0x{hex}")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, [0u8; 32]);
    }

    #[test]
    fn parse_user_nonce_rejects_wrong_length() {
        assert!(parse_user_nonce("0x00").is_err());
        assert!(parse_user_nonce(&"aa".repeat(33)).is_err());
    }

    #[test]
    fn parse_user_nonce_rejects_non_hex() {
        assert!(parse_user_nonce("zz".repeat(32).as_str()).is_err());
    }

    #[test]
    fn attestation_state_returns_identical_cached_arc() {
        let r = AttestationResponse {
            quote: "0xq".into(),
            event_log: String::new(),
            pubkey: "0xp".into(),
            compose_hash: String::new(),
        };
        let s = AttestationState::from_response(r);
        let a = s.response();
        let b = s.response();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
