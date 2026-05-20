//! `/attestation` endpoint — returns a fresh TDX quote bound to the
//! sidecar's signing pubkey and a caller-supplied 32-byte nonce.
//!
//! Every request triggers a `get_quote` round-trip to dstack — the quote
//! is produced on demand, bound to the verifier's challenge. There is no
//! cached quote: a TDX quote is not a thing the enclave "has", it is a
//! thing it produces against given REPORTDATA.
//!
//! REPORTDATA = `signing_pubkey (32B) || user_nonce (32B)` — the
//! signing pubkey is always bound into the quote.
//!
//! The caller MUST supply a 32-byte nonce as `?nonce=<hex>`. Missing or
//! malformed nonce → `400 Bad Request`.
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use dstack_sdk::dstack_client::DstackClient;

use crate::server::AppState;

pub const REPORT_DATA_LEN: usize = 64;
pub const REPORT_DATA_PUBKEY_OFFSET: usize = 0;
pub const REPORT_DATA_NONCE_OFFSET: usize = 32;

#[derive(Clone)]
pub struct AttestationState {
    inner: Arc<AttestationInner>,
}

struct AttestationInner {
    dstack: DstackClient,
    signing_pubkey: [u8; 32],
    compose_hash: String,
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
    /// Connect to dstack and cache the (stable) compose hash from `info`.
    /// No quote is fetched at startup — every quote is produced fresh per
    /// request, bound to the caller's nonce.
    ///
    /// If dstack reports no `compose_hash`, refuse to boot unless the
    /// operator explicitly opts out via `allow_empty_compose_hash` (the
    /// `--allow-empty-compose-hash` CLI flag). Serving `"composeHash": ""`
    /// silently is an operator footgun — clients can't distinguish "build is
    /// not bound to a compose" from "the field is missing."
    pub async fn bootstrap(
        dstack: DstackClient,
        signing_pubkey: [u8; 32],
        allow_empty_compose_hash: bool,
    ) -> Result<Self> {
        let info = dstack.info().await.context("dstack info")?;
        let top_level = (!info.compose_hash.is_empty()).then(|| info.compose_hash.clone());
        let compose_hash = resolve_compose_hash(top_level, allow_empty_compose_hash)?;
        Ok(Self {
            inner: Arc::new(AttestationInner {
                dstack,
                signing_pubkey,
                compose_hash,
            }),
        })
    }

    pub fn compose_hash(&self) -> &str {
        &self.inner.compose_hash
    }

    /// Fetch a TDX quote bound to `REPORTDATA = signing_pubkey || nonce`.
    /// Every call hits dstack — no caching.
    pub async fn get(&self, nonce: [u8; 32]) -> Result<AttestationResponse> {
        let report_data = build_report_data(self.inner.signing_pubkey, nonce);
        let quote = self
            .inner
            .dstack
            .get_quote(report_data.to_vec())
            .await
            .context("dstack get_quote")?;
        Ok(AttestationResponse {
            quote: ensure_0x_prefix(&quote.quote),
            event_log: ensure_0x_prefix(&quote.event_log),
            pubkey: ensure_0x_prefix(&hex::encode(self.inner.signing_pubkey)),
            compose_hash: self.inner.compose_hash.clone(),
        })
    }
}

/// Resolve the boot-time compose hash. `info_compose_hash` is whatever
/// `InfoResponse::compose_hash()` returned (already empty-filtered to
/// `Option<String>`). If absent and the operator did not pass
/// `--allow-empty-compose-hash`, refuse to boot.
pub fn resolve_compose_hash(
    info_compose_hash: Option<String>,
    allow_empty: bool,
) -> Result<String> {
    match info_compose_hash {
        Some(h) => Ok(h),
        None if allow_empty => {
            tracing::warn!(
                "dstack info returned no compose_hash; \
                 continuing because --allow-empty-compose-hash is set. \
                 Production deployments must bind a compose hash."
            );
            Ok(String::new())
        }
        None => anyhow::bail!(
            "dstack info returned no compose_hash; refuse to boot. \
             Pass --allow-empty-compose-hash to override (dev/test only)."
        ),
    }
}

/// Build the REPORTDATA: 32B signing pubkey concatenated with 32B
/// caller-supplied nonce. The pubkey is bound into the quote.
pub fn build_report_data(signing_pubkey: [u8; 32], user_nonce: [u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut out = [0u8; REPORT_DATA_LEN];
    out[REPORT_DATA_PUBKEY_OFFSET..REPORT_DATA_NONCE_OFFSET].copy_from_slice(&signing_pubkey);
    out[REPORT_DATA_NONCE_OFFSET..REPORT_DATA_LEN].copy_from_slice(&user_nonce);
    out
}

pub async fn attestation_handler(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Result<Json<AttestationResponse>, (StatusCode, String)> {
    let nonce = extract_nonce(&query).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    state
        .attestation
        .get(nonce)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))
}

/// Reads the required nonce from `?nonce=<hex>`. Returns `Err` if absent.
pub fn extract_nonce(query: &AttestationQuery) -> Result<[u8; 32]> {
    let raw = query
        .nonce
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing required ?nonce=<32B hex>"))?;
    parse_user_nonce(raw)
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
///
/// **Freshness contract:** the sidecar does not police nonce freshness
/// — callers MUST sample a fresh CSPRNG-generated 32-byte nonce per request.
/// Reused nonces enable replay of captured quotes by a man-in-the-middle and
/// erase the freshness guarantee the nonce-binding is intended to provide.
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
    fn extract_nonce_errors_when_absent() {
        let err = extract_nonce(&AttestationQuery::default()).unwrap_err();
        assert!(
            err.to_string().contains("missing required"),
            "expected missing-nonce error, got: {err}"
        );
    }

    #[test]
    fn extract_nonce_reads_query_parameter() {
        let nonce_hex = format!("0x{}", "ab".repeat(32));
        let parsed = extract_nonce(&AttestationQuery {
            nonce: Some(nonce_hex),
        })
        .unwrap();
        assert_eq!(parsed, [0xab; 32]);
    }

    #[test]
    fn extract_nonce_propagates_parse_error_for_bad_hex() {
        let err = extract_nonce(&AttestationQuery {
            nonce: Some("zz".repeat(32)),
        });
        assert!(err.is_err());
    }

    #[test]
    fn extract_nonce_propagates_parse_error_for_wrong_length() {
        let err = extract_nonce(&AttestationQuery {
            nonce: Some("0xab".into()),
        });
        assert!(err.is_err());
    }

    #[test]
    fn extract_nonce_rejects_empty_string_value() {
        // `?nonce=` parses to Some("") — must not be treated as "absent"
        // and must fail the length check (0 bytes != 32).
        let err = extract_nonce(&AttestationQuery {
            nonce: Some(String::new()),
        });
        assert!(err.is_err(), "empty nonce value must be rejected");
    }

    #[test]
    fn parse_user_nonce_accepts_uppercase_hex() {
        let lower = "ab".repeat(32);
        let upper = "AB".repeat(32);
        assert_eq!(parse_user_nonce(&lower).unwrap(), [0xab; 32]);
        assert_eq!(parse_user_nonce(&upper).unwrap(), [0xab; 32]);
    }

    #[test]
    fn parse_user_nonce_accepts_uppercase_0x_prefix() {
        let v = format!("0X{}", "cd".repeat(32));
        assert_eq!(parse_user_nonce(&v).unwrap(), [0xcd; 32]);
    }

    #[test]
    fn parse_user_nonce_rejects_odd_length_hex() {
        assert!(parse_user_nonce(&"a".repeat(63)).is_err());
        assert!(parse_user_nonce(&format!("0x{}", "a".repeat(63))).is_err());
    }

    #[test]
    fn parse_user_nonce_trims_surrounding_whitespace() {
        let raw = format!("  0x{}  ", "ee".repeat(32));
        assert_eq!(parse_user_nonce(&raw).unwrap(), [0xee; 32]);
    }

    // The handler accepts the query via axum's `Query<T>` extractor, which
    // delegates to `serde_urlencoded`. Exercise the same parse path to be
    // sure the URL-level shape lines up with the in-memory struct used by
    // the unit tests above.
    #[test]
    fn query_string_deserialises_into_attestation_query() {
        let q: AttestationQuery =
            serde_urlencoded::from_str(&format!("nonce=0x{}", "11".repeat(32))).unwrap();
        let parsed = extract_nonce(&q).unwrap();
        assert_eq!(parsed, [0x11; 32]);
    }

    #[test]
    fn query_string_with_no_nonce_key_yields_none() {
        let q: AttestationQuery = serde_urlencoded::from_str("other=value").unwrap();
        assert!(q.nonce.is_none());
        assert!(extract_nonce(&q).is_err());
    }

    #[test]
    fn query_string_with_empty_value_yields_some_empty() {
        // ?nonce= → Some("") — caught by the wrong-length check, not by
        // the "absent" branch.
        let q: AttestationQuery = serde_urlencoded::from_str("nonce=").unwrap();
        assert_eq!(q.nonce.as_deref(), Some(""));
        assert!(extract_nonce(&q).is_err());
    }

    #[test]
    fn resolve_compose_hash_returns_value_when_present() {
        // present hash is passed through regardless of the flag.
        let h = resolve_compose_hash(Some("abcd".to_string()), false).unwrap();
        assert_eq!(h, "abcd");
        let h = resolve_compose_hash(Some("abcd".to_string()), true).unwrap();
        assert_eq!(h, "abcd");
    }

    #[test]
    fn resolve_compose_hash_errors_when_empty_and_not_allowed() {
        // absent hash with no override is a hard boot error.
        let err = resolve_compose_hash(None, false).unwrap_err();
        assert!(
            err.to_string().contains("no compose_hash"),
            "expected compose_hash error, got: {err}"
        );
    }

    #[test]
    fn resolve_compose_hash_returns_empty_when_explicitly_allowed() {
        // with --allow-empty-compose-hash, absent maps to empty string.
        let h = resolve_compose_hash(None, true).unwrap();
        assert_eq!(h, "");
    }

    #[test]
    fn query_string_with_duplicate_nonce_is_rejected() {
        // `serde_urlencoded` fails on duplicate scalar fields — so the
        // axum extractor will reject `?nonce=a&nonce=b` with 400 before
        // the handler ever runs. Verifying that behaviour here so a
        // future `serde_urlencoded` upgrade doesn't silently change it.
        let err = serde_urlencoded::from_str::<AttestationQuery>(&format!(
            "nonce=0x{}&nonce=0x{}",
            "11".repeat(32),
            "22".repeat(32)
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("duplicate"),
            "expected duplicate-field error, got: {err}"
        );
    }
}
