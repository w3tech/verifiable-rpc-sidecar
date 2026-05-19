//! `/attestation` endpoint — returns a TDX quote bound to the sidecar's
//! signing pubkey and a caller-supplied 32-byte nonce.
//!
//! The default response (`nonce = 0x00…`) is fetched once at startup and
//! cached for the process lifetime. Requests carrying a non-default nonce
//! trigger a fresh `get_quote` round-trip to dstack — that is the whole
//! point of the user nonce: the verifier supplies a challenge, the enclave
//! returns a quote bound to it, defeating quote replay.
//!
//! REPORTDATA = `signing_pubkey (32B) || user_nonce (32B)` per SPEC-05
//! (closes C3 — signing pubkey is always bound into the quote).
//!
//! Nonce sources, in priority order:
//! 1. `?nonce=<hex>` query parameter
//! 2. `X-Phala-Nonce: <hex>` header
//! 3. default (32 zero bytes — returns the cached startup quote)
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::dstack::DstackClient;
use crate::server::AppState;

pub const REPORT_DATA_LEN: usize = 64;
pub const REPORT_DATA_PUBKEY_OFFSET: usize = 0;
pub const REPORT_DATA_NONCE_OFFSET: usize = 32;
pub const NONCE_HEADER: &str = "X-Phala-Nonce";

const ZERO_NONCE: [u8; 32] = [0u8; 32];

#[derive(Clone)]
pub struct AttestationState {
    inner: Arc<AttestationInner>,
}

struct AttestationInner {
    dstack: DstackClient,
    signing_pubkey: [u8; 32],
    compose_hash: String,
    default_response: AttestationResponse,
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

#[derive(Debug, Default, Deserialize)]
pub struct AttestationQuery {
    pub nonce: Option<String>,
}

impl AttestationState {
    pub async fn bootstrap(dstack: DstackClient, signing_pubkey: [u8; 32]) -> Result<Self> {
        let info = dstack.info().await.context("dstack info")?;
        let compose_hash = info.compose_hash().unwrap_or_default();
        let default_response =
            build_response(&dstack, signing_pubkey, ZERO_NONCE, &compose_hash).await?;
        Ok(Self {
            inner: Arc::new(AttestationInner {
                dstack,
                signing_pubkey,
                compose_hash,
                default_response,
            }),
        })
    }

    pub fn compose_hash(&self) -> &str {
        &self.inner.compose_hash
    }

    /// The cached zero-nonce response — fetched once at startup.
    pub fn default_response(&self) -> &AttestationResponse {
        &self.inner.default_response
    }

    /// Returns a quote bound to `nonce`. The all-zero nonce returns the
    /// cached startup response; any other nonce triggers a fresh `get_quote`
    /// round-trip to dstack.
    pub async fn get(&self, nonce: [u8; 32]) -> Result<AttestationResponse> {
        if nonce == ZERO_NONCE {
            return Ok(self.inner.default_response.clone());
        }
        build_response(
            &self.inner.dstack,
            self.inner.signing_pubkey,
            nonce,
            &self.inner.compose_hash,
        )
        .await
    }
}

async fn build_response(
    dstack: &DstackClient,
    signing_pubkey: [u8; 32],
    nonce: [u8; 32],
    compose_hash: &str,
) -> Result<AttestationResponse> {
    let report_data = build_report_data(signing_pubkey, nonce);
    let quote = dstack
        .get_quote(&report_data)
        .await
        .context("dstack get_quote")?;
    Ok(AttestationResponse {
        quote: ensure_0x_prefix(&quote.quote),
        event_log: ensure_0x_prefix(&quote.event_log),
        pubkey: ensure_0x_prefix(&hex::encode(signing_pubkey)),
        compose_hash: compose_hash.to_string(),
    })
}

/// Build the SPEC-05 REPORTDATA: 32B signing pubkey concatenated with 32B
/// caller-supplied nonce. Closes C3 — the pubkey is bound into the quote.
pub fn build_report_data(signing_pubkey: [u8; 32], user_nonce: [u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[REPORT_DATA_PUBKEY_OFFSET..REPORT_DATA_NONCE_OFFSET].copy_from_slice(&signing_pubkey);
    out[REPORT_DATA_NONCE_OFFSET..REPORT_DATA_LEN].copy_from_slice(&user_nonce);
    out
}

pub async fn attestation_handler(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
    headers: HeaderMap,
) -> Result<Json<AttestationResponse>, (StatusCode, String)> {
    let nonce =
        extract_nonce(&query, &headers).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .attestation
        .get(nonce)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
}

/// Pulls the nonce out of `?nonce=…` (priority) or `X-Phala-Nonce` header.
/// Defaults to 32 zero bytes if neither is present.
pub fn extract_nonce(query: &AttestationQuery, headers: &HeaderMap) -> Result<[u8; 32]> {
    let source: Option<&str> = query
        .nonce
        .as_deref()
        .or_else(|| headers.get(NONCE_HEADER).and_then(|v| v.to_str().ok()));
    match source {
        Some(s) => parse_user_nonce(s),
        None => Ok(ZERO_NONCE),
    }
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
    use axum::http::HeaderValue;

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
        assert!(!s.contains("event_log"));
        assert!(!s.contains("compose_hash"));
    }

    #[test]
    fn ensure_0x_prefix_does_not_double_prefix() {
        assert_eq!(ensure_0x_prefix("0xabc"), "0xabc");
        assert_eq!(ensure_0x_prefix("abc"), "0xabc");
        assert_eq!(ensure_0x_prefix(""), "");
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
    fn extract_nonce_defaults_to_zero_when_absent() {
        let query = AttestationQuery::default();
        let headers = HeaderMap::new();
        assert_eq!(extract_nonce(&query, &headers).unwrap(), ZERO_NONCE);
    }

    #[test]
    fn extract_nonce_reads_query_parameter() {
        let nonce_hex = format!("0x{}", "ab".repeat(32));
        let query = AttestationQuery {
            nonce: Some(nonce_hex),
        };
        let headers = HeaderMap::new();
        let parsed = extract_nonce(&query, &headers).unwrap();
        assert_eq!(parsed, [0xab; 32]);
    }

    #[test]
    fn extract_nonce_reads_header_when_no_query() {
        let query = AttestationQuery::default();
        let mut headers = HeaderMap::new();
        let nonce_hex = "cd".repeat(32);
        headers.insert(NONCE_HEADER, HeaderValue::from_str(&nonce_hex).unwrap());
        let parsed = extract_nonce(&query, &headers).unwrap();
        assert_eq!(parsed, [0xcd; 32]);
    }

    #[test]
    fn extract_nonce_query_wins_when_both_present() {
        let query = AttestationQuery {
            nonce: Some("ee".repeat(32)),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            NONCE_HEADER,
            HeaderValue::from_str(&"11".repeat(32)).unwrap(),
        );
        let parsed = extract_nonce(&query, &headers).unwrap();
        assert_eq!(parsed, [0xee; 32]);
    }

    #[test]
    fn extract_nonce_propagates_parse_error_for_bad_hex() {
        let query = AttestationQuery {
            nonce: Some("zz".repeat(32)),
        };
        let headers = HeaderMap::new();
        assert!(extract_nonce(&query, &headers).is_err());
    }

    #[test]
    fn extract_nonce_propagates_parse_error_for_wrong_length() {
        let query = AttestationQuery {
            nonce: Some("0xab".into()),
        };
        let headers = HeaderMap::new();
        assert!(extract_nonce(&query, &headers).is_err());
    }
}
