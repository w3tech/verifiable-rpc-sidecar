//! Minimal client for the dstack-guest-agent JSON-over-HTTP API exposed on a
//! Unix domain socket inside the TDX CVM (or on the local simulator).
//!
//! Wire format mirrors `dstack-sdk` (crates.io) without pulling in `reqwest`
//! and its transitive `rustls` dependency — the sidecar's Cargo manifest
//! intentionally contains no TLS crates (C1 / pitfall mitigation).
//!
//! Default socket path matches the agent default of `/var/run/dstack.sock`;
//! override via `DSTACK_SIMULATOR_ENDPOINT` for the
//! [Phala dstack local simulator](https://docs.phala.com/dstack/local-development).
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const DEFAULT_SOCKET: &str = "/var/run/dstack.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1 << 20; // 1 MiB — quotes + event logs fit comfortably.

#[derive(Clone, Debug)]
pub struct DstackClient {
    socket: PathBuf,
}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        let socket = match endpoint {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => match std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok() {
                Some(p) if !p.is_empty() => PathBuf::from(p),
                _ => PathBuf::from(DEFAULT_SOCKET),
            },
        };
        Self { socket }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub async fn get_key(
        &self,
        path: Option<&str>,
        purpose: Option<&str>,
    ) -> Result<GetKeyResponse> {
        let body = json!({
            "path": path.unwrap_or_default(),
            "purpose": purpose.unwrap_or_default(),
        });
        let raw = self.post("/GetKey", &body).await?;
        serde_json::from_value::<GetKeyResponse>(raw).context("decode GetKey response")
    }

    pub async fn get_quote(&self, report_data: &[u8]) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            bail!(
                "report_data must be 1..=64 bytes, got {}",
                report_data.len()
            );
        }
        let body = json!({ "report_data": hex::encode(report_data) });
        let raw = self.post("/GetQuote", &body).await?;
        serde_json::from_value::<GetQuoteResponse>(raw).context("decode GetQuote response")
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let raw = self.post("/Info", &json!({})).await?;
        serde_json::from_value::<InfoResponse>(raw).context("decode Info response")
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(body).context("serialise request body")?;
        let response_bytes = timeout(REQUEST_TIMEOUT, self.send(path, &bytes))
            .await
            .with_context(|| format!("dstack {path}: timed out after {REQUEST_TIMEOUT:?}"))??;
        // Some dstack endpoints (e.g. `/EmitEvent`) return an empty body.
        if response_bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice::<Value>(&response_bytes)
            .with_context(|| format!("dstack {path}: response was not valid JSON"))
    }

    async fn send(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect to dstack socket {:?}", self.socket))?;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if raw.len() + n > MAX_RESPONSE_BYTES {
                bail!("dstack response exceeded {MAX_RESPONSE_BYTES} bytes");
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        parse_http_response(&raw)
    }
}

/// Parse a buffered HTTP/1.x response from the dstack agent UDS connection.
///
/// Uses `httparse` (WR-06) so we correctly handle:
/// - HTTP/1.0 and HTTP/1.1 status lines
/// - mixed CRLF/LF tolerance via httparse
/// - response sizes up to `MAX_RESPONSE_BYTES` (cap enforced upstream in `send`)
///
/// `Transfer-Encoding: chunked` is **rejected loudly** rather than silently
/// dropping the body — the dstack agents we target use `Content-Length`, so a
/// chunked response signals an upstream change we want to surface immediately.
fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>> {
    // 64 headers is generous for dstack's tiny response; bump if dstack ever
    // adds more (httparse fails loudly with TooManyHeaders rather than truncating).
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let body_offset = match response
        .parse(raw)
        .map_err(|e| anyhow!("malformed http response: {e}"))?
    {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => bail!("malformed http response: header section incomplete"),
    };

    let status = response
        .code
        .ok_or_else(|| anyhow!("malformed http response: missing status code"))?;
    let body = &raw[body_offset..];

    // Reject chunked TE explicitly — silently passing chunk framing through to
    // serde_json would surface as cryptic JSON-parse errors. If a future dstack
    // build switches to chunked we'd rather notice loud here.
    if response
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding") && contains_chunked(h.value))
    {
        bail!(
            "dstack response uses Transfer-Encoding: chunked which is not supported; \
             pin the dstack agent version or update parse_http_response to decode chunks"
        );
    }

    if !(200..300).contains(&status) {
        bail!(
            "dstack returned status {status}: {}",
            String::from_utf8_lossy(body)
        );
    }
    Ok(body.to_vec())
}

fn contains_chunked(value: &[u8]) -> bool {
    // Transfer-Encoding can be a comma-separated list (`gzip, chunked`). Match
    // case-insensitively on whole tokens.
    std::str::from_utf8(value)
        .map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .any(|t| t.eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
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
    fn parse_http_response_strips_headers() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: application/json\r\n\r\nhello";
        let body = parse_http_response(raw).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn parse_http_response_rejects_non_2xx() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nERR";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn parse_http_response_rejects_missing_terminator() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn parse_http_response_accepts_http_1_0() {
        // WR-06: httparse handles HTTP/1.0 cleanly.
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let body = parse_http_response(raw).unwrap();
        assert_eq!(body, b"ok");
    }

    #[test]
    fn parse_http_response_rejects_chunked_transfer_encoding() {
        // WR-06: chunked TE is rejected loudly rather than silently corrupting
        // the JSON-parse step.
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let err = parse_http_response(raw).unwrap_err();
        assert!(
            err.to_string().contains("Transfer-Encoding: chunked"),
            "expected chunked-TE rejection, got: {err}"
        );
    }

    #[test]
    fn parse_http_response_rejects_chunked_in_te_list() {
        // `Transfer-Encoding: gzip, chunked` — match the `chunked` token,
        // not just the full value string.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert!(parse_http_response(raw).is_err());
    }

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
