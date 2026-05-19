//! Minimal client for the dstack-guest-agent JSON-over-HTTP API exposed on a
//! Unix domain socket inside the TDX CVM (or on the local simulator).
//!
//! Wire format mirrors `dstack-sdk` (crates.io) without pulling in `reqwest`
//! and its transitive `rustls` dependency — the sidecar's Cargo manifest
//! intentionally contains no TLS crates.
//!
//! Default socket path matches the agent default of `/var/run/dstack.sock`;
//! override via `DSTACK_SIMULATOR_ENDPOINT` for the
//! [Phala dstack local simulator](https://docs.phala.com/dstack/local-development).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

const DEFAULT_SOCKET: &str = "/var/run/dstack.sock";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Default cap on a single dstack response, used when a `DstackClient`
/// is built without an explicit override (i.e. via `DstackClient::new`). 16 MiB
/// fits even oversized RTMR event logs while still bounding worst-case memory
/// growth from a misbehaving agent.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct DstackClient {
    socket: PathBuf,
    max_response_bytes: usize,
    /// Single long-lived UDS connection reused across requests. Reuse is
    /// serialized via a `Mutex` — multiple in-flight `/attestation` requests
    /// still wait their turn (the dstack agent itself serialises quote
    /// generation), but the connect cost amortises across calls instead of
    /// being paid every request.
    ///
    /// Tradeoff: we don't get *parallel* quote generation (would need a real
    /// pool of N connections), but we do get rid of the per-request UDS
    /// handshake. On any I/O error the connection is dropped and the next
    /// call reconnects.
    pool: Arc<Mutex<Option<UnixStream>>>,
}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        Self::with_max_response_bytes(endpoint, DEFAULT_MAX_RESPONSE_BYTES)
    }

    /// Construct with a caller-supplied response-size cap (plumbed in
    /// from the `--dstack-max-response-bytes` CLI flag).
    pub fn with_max_response_bytes(endpoint: Option<&str>, max_response_bytes: usize) -> Self {
        let socket = match endpoint {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => match std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok() {
                Some(p) if !p.is_empty() => PathBuf::from(p),
                _ => PathBuf::from(DEFAULT_SOCKET),
            },
        };
        Self {
            socket,
            max_response_bytes,
            pool: Arc::new(Mutex::new(None)),
        }
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
        // Serialise access through the pool. The agent itself can only
        // produce one quote at a time, so concurrency here would not help
        // anyway — we just don't pay the UDS handshake on every call.
        let mut slot = self.pool.lock().await;

        // Borrow the cached stream or reconnect on first use / after error.
        let stream = match slot.as_mut() {
            Some(s) => s,
            None => {
                let s = UnixStream::connect(&self.socket)
                    .await
                    .with_context(|| format!("connect to dstack socket {:?}", self.socket))?;
                slot.insert(s)
            }
        };

        // Run the round-trip; drop the connection on *any* error so the next
        // call reconnects cleanly. The agent's persistent-connection behaviour
        // is not contractual on UDS, so we don't risk a wedged stream.
        match send_once(stream, path, body, self.max_response_bytes).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                slot.take();
                Err(e)
            }
        }
    }
}

/// One HTTP/1.1 request/response on an established UDS connection. No
/// `Connection: close` header — we want the agent to keep the socket open
/// across requests. Reads exactly Content-Length bytes; rejects chunked TE
/// upstream in `parse_http_response`.
async fn send_once(
    stream: &mut UnixStream,
    path: &str,
    body: &[u8],
    max_response_bytes: usize,
) -> Result<Vec<u8>> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;

    // Read header section first (bounded by max_response_bytes), then drain
    // Content-Length more bytes. We don't fall back to EOF-framing here:
    // dstack always emits Content-Length, and a missing header is a
    // protocol error rather than something we silently work around.
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let (header_end, content_length) = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("dstack closed connection mid-headers");
        }
        if raw.len() + n > max_response_bytes {
            bail!("dstack response exceeded {max_response_bytes} bytes (cap)");
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some((end, cl)) = peek_header_end(&raw)? {
            break (end, cl);
        }
    };

    let target_total = header_end
        .checked_add(content_length)
        .ok_or_else(|| anyhow!("dstack Content-Length overflow"))?;
    if target_total > max_response_bytes {
        bail!(
            "dstack Content-Length {content_length} exceeds cap (header + body would be {target_total} > {max_response_bytes})"
        );
    }
    while raw.len() < target_total {
        let want = target_total - raw.len();
        let cap = chunk.len().min(want);
        let n = stream.read(&mut chunk[..cap]).await?;
        if n == 0 {
            bail!(
                "dstack closed connection with {} of {content_length} body bytes pending",
                target_total - raw.len()
            );
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    raw.truncate(target_total);
    parse_http_response(&raw)
}

/// Returns `Some((header_section_len, content_length))` once `raw` contains a
/// complete header section, or `None` if more bytes are needed. Errors if the
/// headers are malformed or `Content-Length` is missing/invalid.
fn peek_header_end(raw: &[u8]) -> Result<Option<(usize, usize)>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response
        .parse(raw)
        .map_err(|e| anyhow!("malformed http response: {e}"))?
    {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete(end) => {
            let cl = response
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                .ok_or_else(|| anyhow!("dstack response missing Content-Length"))?;
            let cl: usize = std::str::from_utf8(cl.value)
                .map_err(|_| anyhow!("dstack Content-Length not ASCII"))?
                .trim()
                .parse()
                .map_err(|e| anyhow!("dstack Content-Length not a number: {e}"))?;
            Ok(Some((end, cl)))
        }
    }
}

/// Parse a buffered HTTP/1.x response from the dstack agent UDS connection.
///
/// Uses `httparse` so we correctly handle:
/// - HTTP/1.0 and HTTP/1.1 status lines
/// - mixed CRLF/LF tolerance via httparse
/// - response sizes up to `max_response_bytes` (cap enforced upstream in `send`)
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
        // httparse handles HTTP/1.0 cleanly.
        let raw = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let body = parse_http_response(raw).unwrap();
        assert_eq!(body, b"ok");
    }

    #[test]
    fn parse_http_response_rejects_chunked_transfer_encoding() {
        // Chunked TE is rejected loudly rather than silently corrupting
        // the JSON-parse step.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
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

    /// Mock dstack agent serving a fixed body. Returns the live temp
    /// socket and TempDir handle so callers can keep them alive for the
    /// duration of the test.
    async fn spawn_mock_with_body(body: Vec<u8>) -> (tempfile::TempDir, PathBuf) {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixListener;
        let tmp = tempfile::TempDir::new().unwrap();
        let socket = tmp.path().join("d.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let body_size = body.len();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the small POST request — the client uses Connection: close
            // so we'll EOF naturally after the response.
            let mut scratch = [0u8; 4096];
            let _ = stream.read(&mut scratch).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {body_size}\r\nContent-Type: application/json\r\n\r\n"
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.flush().await.unwrap();
            drop(stream);
        });
        (tmp, socket)
    }

    /// Mock dstack that serves `responses.len()` requests on a single
    /// persistent connection. After the final response it closes; if the
    /// client opens a *second* connection (which would imply we paid the
    /// handshake again), `extra_connects` increments — the test asserts on it.
    async fn spawn_persistent_mock(
        responses: Vec<Vec<u8>>,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::AtomicUsize;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixListener;
        let tmp = tempfile::TempDir::new().unwrap();
        let socket = tmp.path().join("d.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let connect_count = Arc::new(AtomicUsize::new(0));
        let connect_count_clone = connect_count.clone();
        tokio::spawn(async move {
            // Only the first accept matters for the assertion; subsequent
            // accepts increment so the test can prove we *didn't* reconnect.
            let mut first = true;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                if first {
                    first = false;
                } else {
                    connect_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let responses = responses.clone();
                tokio::spawn(async move {
                    for body in responses {
                        // Read one request: scan until \r\n\r\n then read
                        // Content-Length bytes of the request body.
                        let mut buf = Vec::with_capacity(1024);
                        let mut tmp_buf = [0u8; 1024];
                        let req_cl = loop {
                            let n = match stream.read(&mut tmp_buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&tmp_buf[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                // Parse Content-Length from headers.
                                let head = &buf[..pos];
                                let head_s = std::str::from_utf8(head).unwrap_or("");
                                let cl = head_s
                                    .lines()
                                    .find_map(|l| {
                                        let mut parts = l.splitn(2, ':');
                                        let (n, v) = (parts.next()?, parts.next()?);
                                        if n.trim().eq_ignore_ascii_case("content-length") {
                                            v.trim().parse::<usize>().ok()
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(0);
                                buf.drain(..pos + 4);
                                break cl;
                            }
                        };
                        while buf.len() < req_cl {
                            let mut t = [0u8; 1024];
                            let n = match stream.read(&mut t).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&t[..n]);
                        }
                        // Send response.
                        let head = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                            body.len()
                        );
                        if stream.write_all(head.as_bytes()).await.is_err() {
                            return;
                        }
                        if stream.write_all(&body).await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (tmp, socket, connect_count)
    }

    #[tokio::test]
    async fn dstack_reuses_connection_across_sequential_calls() {
        // Two sequential `post` calls should ride the same socket.
        // The mock counts re-accepts; assert zero second accepts.
        let (_tmp, socket, connect_count) =
            spawn_persistent_mock(vec![b"\"first\"".to_vec(), b"\"second\"".to_vec()]).await;
        let client = DstackClient::with_max_response_bytes(
            Some(socket.to_str().unwrap()),
            DEFAULT_MAX_RESPONSE_BYTES,
        );

        let r1 = client.post("/A", &serde_json::json!({})).await.unwrap();
        let r2 = client.post("/B", &serde_json::json!({})).await.unwrap();
        assert_eq!(r1, serde_json::Value::String("first".to_string()));
        assert_eq!(r2, serde_json::Value::String("second".to_string()));
        // Give the listener task a tick to register any stray accept.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            connect_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "second post should reuse the existing UDS connection"
        );
    }

    #[tokio::test]
    async fn dstack_request_omits_connection_close_header() {
        // The request line must NOT carry `Connection: close` —
        // verify by inspecting the bytes the server received on the wire.
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixListener;
        let tmp = tempfile::TempDir::new().unwrap();
        let socket = tmp.path().join("d.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let cap = captured.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            // One read is enough to capture the request head + tiny body.
            let n = stream.read(&mut buf).await.unwrap();
            cap.lock().await.extend_from_slice(&buf[..n]);
            let body = b"\"ok\"";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            stream.flush().await.unwrap();
        });
        let client = DstackClient::with_max_response_bytes(
            Some(socket.to_str().unwrap()),
            DEFAULT_MAX_RESPONSE_BYTES,
        );
        let _ = client.post("/X", &serde_json::json!({})).await.unwrap();
        let bytes = captured.lock().await;
        let request_text = String::from_utf8_lossy(&bytes);
        assert!(
            !request_text.to_lowercase().contains("connection: close"),
            "request must not contain `Connection: close`, saw:\n{request_text}"
        );
    }

    #[tokio::test]
    async fn dstack_response_within_cap_succeeds() {
        // 4 byte JSON body, cap 4 KiB — must succeed end-to-end.
        let body = b"\"ok\"".to_vec();
        let (_tmp, socket) = spawn_mock_with_body(body).await;
        let client =
            DstackClient::with_max_response_bytes(Some(socket.to_str().unwrap()), 4 * 1024);
        let parsed = client
            .post("/AnyPath", &serde_json::json!({}))
            .await
            .expect("response under cap must succeed");
        assert_eq!(parsed, serde_json::Value::String("ok".to_string()));
    }

    #[tokio::test]
    async fn dstack_response_over_cap_errors_loudly() {
        // 2 KiB padded JSON, cap 1 KiB — must error with a message
        // mentioning the cap so operators know what knob to turn.
        let body = vec![b'x'; 2 * 1024];
        let (_tmp, socket) = spawn_mock_with_body(body).await;
        let client = DstackClient::with_max_response_bytes(Some(socket.to_str().unwrap()), 1024);
        let err = client
            .post("/AnyPath", &serde_json::json!({}))
            .await
            .expect_err("response over cap must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeded") && msg.contains("bytes"),
            "expected cap-exceeded message, got: {msg}"
        );
    }

    #[test]
    fn dstack_client_new_uses_default_cap() {
        let c = DstackClient::new(Some("/tmp/x.sock"));
        assert_eq!(c.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
    }

    #[test]
    fn dstack_client_honours_explicit_cap() {
        let c = DstackClient::with_max_response_bytes(Some("/tmp/x.sock"), 12345);
        assert_eq!(c.max_response_bytes, 12345);
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
