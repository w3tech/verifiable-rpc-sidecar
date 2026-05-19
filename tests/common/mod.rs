//! Test harness for integration tests.
//!
//! Self-contained helpers used by `tests/integration.rs`:
//! - `SimulatorHandle` — spawns the dstack-guest-agent-simulator in a fresh
//!   temp dir; cleans up on drop.
//! - `SidecarHandle` — spawns the `rpc-attest-sidecar` binary against a given
//!   upstream + dstack socket; parses `signing_pubkey` from boot log.
//! - `MockUpstream` — tiny tokio HTTP server serving a canned response and
//!   recording received requests.
//! - `HttpClient` — wrapper around `hyper_util` legacy `Client` for plain HTTP
//!   calls to the sidecar.
//! - `verify_signed_response` — Ed25519-verifies a sidecar-signed response
//!   against the canonical 80-byte pre-image.
//!
//! Required env vars (see `tests/integration.rs` for which tier needs which):
//!   DSTACK_SIMULATOR_BIN          — absolute path to the `dstack-simulator` binary
//!   DSTACK_SIMULATOR_FIXTURES_DIR — directory containing app-compose.json, appkeys.json, etc.
//!   SHARK_RPC_URL                 — full upstream URL (live shark tests only)
//!   SHARK_API_KEY                 — value for the `x-api-key` header (live shark tests only)

#![allow(dead_code)] // helpers are pulled in per-test; not every one is used by every group

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{BufRead, BufReader};
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ed25519_dalek::{Verifier, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Method;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Marker error type so tests can `unwrap()` with reasonable messages.
type TestResult<T> = Result<T, String>;

/// Convert anything implementing `Display` into a `String` error.
fn to_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

// ===== Env helpers =====

pub fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

pub fn require_env(name: &str) -> String {
    env_var(name).unwrap_or_else(|| {
        panic!(
            "env var `{name}` is required for integration tests — see tests/common/mod.rs header"
        )
    })
}

// ===== Simulator =====

pub struct SimulatorHandle {
    child: Child,
    _tmp: TempDir,
    socket: PathBuf,
}

impl SimulatorHandle {
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for SimulatorHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn spawn_simulator() -> SimulatorHandle {
    let bin = require_env("DSTACK_SIMULATOR_BIN");
    let fixtures = require_env("DSTACK_SIMULATOR_FIXTURES_DIR");

    let tmp = TempDir::new().expect("create simulator tmpdir");
    for f in [
        "app-compose.json",
        "appkeys.json",
        "attestation.bin",
        "dstack.toml",
        "sys-config.json",
    ] {
        let src = PathBuf::from(&fixtures).join(f);
        let dst = tmp.path().join(f);
        std::fs::copy(&src, &dst)
            .unwrap_or_else(|e| panic!("copy fixture {f} from {src:?} to {dst:?}: {e}"));
    }

    let child = Command::new(&bin)
        .current_dir(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn simulator {bin}: {e}"));

    let socket = tmp.path().join("dstack.sock");
    wait_for_path(&socket, Duration::from_secs(5)).expect("simulator socket did not appear");

    SimulatorHandle {
        child,
        _tmp: tmp,
        socket,
    }
}

fn wait_for_path(p: &Path, max: Duration) -> TestResult<()> {
    let started = Instant::now();
    while started.elapsed() < max {
        if p.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timeout waiting for {p:?}"))
}

fn wait_for_listener(port: u16, max: Duration) -> TestResult<()> {
    let started = Instant::now();
    let addr = format!("127.0.0.1:{port}");
    while started.elapsed() < max {
        if std::net::TcpStream::connect_timeout(
            &addr.parse().expect("parse addr"),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timeout waiting for listener on 127.0.0.1:{port}"))
}

// ===== Sidecar =====

pub struct SidecarHandle {
    child: Child,
    pub base_url: String,
    pub signing_pubkey: [u8; 32],
    pub chain_id: u64,
    stdout_join: Option<JoinHandle<()>>,
    captured: Arc<Mutex<Vec<String>>>,
}

impl SidecarHandle {
    pub fn captured(&self) -> Vec<String> {
        self.captured.lock().unwrap().clone()
    }

    pub fn signing_pubkey_hex(&self) -> String {
        format!("0x{}", hex::encode(self.signing_pubkey))
    }

    pub fn as_ref_(&self) -> SidecarRef {
        SidecarRef {
            base_url: self.base_url.clone(),
            signing_pubkey: self.signing_pubkey,
            chain_id: self.chain_id,
        }
    }
}

/// Minimal reference to a sidecar that's already running somewhere.
///
/// Returned by `acquire_blackbox_sidecar()` so the same test function can
/// drive either a locally-spawned sidecar or an externally deployed one.
#[derive(Clone, Debug)]
pub struct SidecarRef {
    pub base_url: String,
    pub signing_pubkey: [u8; 32],
    pub chain_id: u64,
}

/// Acquired sidecar — either an `External` reference (no cleanup) or a `Local`
/// bundle that owns the spawned `SidecarHandle`, `SimulatorHandle`, and any
/// supporting `MockUpstream` so RAII cleanup just works.
pub enum SidecarAcquisition {
    External(SidecarRef),
    Local(LocalSidecar),
}

pub struct LocalSidecar {
    // Order matters for Drop: sidecar first, then simulator, then upstream.
    pub sidecar: SidecarHandle,
    pub simulator: SimulatorHandle,
    pub upstream: MockUpstream,
}

impl SidecarAcquisition {
    pub fn as_ref(&self) -> SidecarRef {
        match self {
            SidecarAcquisition::External(r) => r.clone(),
            SidecarAcquisition::Local(l) => l.sidecar.as_ref_(),
        }
    }

    /// Indicates whether the test can poke an in-process mock upstream
    /// (true) or must treat the sidecar as a black box (false).
    pub fn has_mock_upstream(&self) -> bool {
        matches!(self, SidecarAcquisition::Local(_))
    }

    pub fn mock_upstream(&self) -> Option<&MockUpstream> {
        match self {
            SidecarAcquisition::Local(l) => Some(&l.upstream),
            SidecarAcquisition::External(_) => None,
        }
    }
}

/// Acquire a sidecar to test against — either an externally-deployed one
/// referenced via env vars, or a freshly-spawned local one wired to a fresh
/// simulator + mock upstream.
///
/// Env:
///   SIDECAR_URL                — base URL of an already-running sidecar
///   SIDECAR_CHAIN_ID           — chain_id that sidecar is configured with
///                                (needed to rebuild the signing pre-image)
///
/// Either both are set (external mode) or neither is set (local mode). Local
/// mode requires the usual `DSTACK_SIMULATOR_BIN` + `DSTACK_SIMULATOR_FIXTURES_DIR`.
pub async fn acquire_blackbox_sidecar() -> SidecarAcquisition {
    if let (Some(url), Some(chain_id)) = (env_var("SIDECAR_URL"), env_var("SIDECAR_CHAIN_ID")) {
        let chain_id: u64 = chain_id
            .parse()
            .unwrap_or_else(|e| panic!("SIDECAR_CHAIN_ID is not a u64: {e}"));
        let pubkey = fetch_pubkey_from_attestation(&url)
            .await
            .unwrap_or_else(|e| panic!("could not bootstrap pubkey from {url}/attestation: {e}"));
        return SidecarAcquisition::External(SidecarRef {
            base_url: url,
            signing_pubkey: pubkey,
            chain_id,
        });
    }
    let simulator = spawn_simulator();
    let upstream = MockUpstream::start().await;
    let sidecar = spawn_sidecar(SidecarSpawn {
        upstream_url: &upstream.url.clone(),
        chain_id: 1,
        dstack_endpoint: simulator.socket(),
        extra_env: vec![],
    });
    SidecarAcquisition::Local(LocalSidecar {
        sidecar,
        simulator,
        upstream,
    })
}

/// Resolve the sidecar's signing pubkey by hitting `/attestation` with a
/// zero nonce. Works against any running sidecar — used by the external-mode
/// branch of `acquire_blackbox_sidecar`.
pub async fn fetch_pubkey_from_attestation(base_url: &str) -> TestResult<[u8; 32]> {
    let client = http_client();
    let nonce = format!("0x{}", "00".repeat(32));
    let resp = get(
        &client,
        &format!(
            "{}/attestation?nonce={nonce}",
            base_url.trim_end_matches('/')
        ),
    )
    .await?;
    if !resp.status.is_success() {
        return Err(format!(
            "GET /attestation returned {}: {}",
            resp.status,
            String::from_utf8_lossy(&resp.body)
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&resp.body).map_err(to_err)?;
    let pk_str = v
        .get("pubkey")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "missing pubkey field in /attestation response".to_string())?;
    let bytes = decode_hex_0x(pk_str);
    if bytes.len() != 32 {
        return Err(format!("pubkey must be 32B, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

impl Drop for SidecarHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(h) = self.stdout_join.take() {
            let _ = h.join();
        }
    }
}

pub fn ephemeral_port() -> u16 {
    let l = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

pub struct SidecarSpawn<'a> {
    pub upstream_url: &'a str,
    pub chain_id: u64,
    pub dstack_endpoint: &'a Path,
    pub extra_env: Vec<(&'a str, &'a str)>,
}

pub fn spawn_sidecar(args: SidecarSpawn) -> SidecarHandle {
    let port = ephemeral_port();
    let bin = env!("CARGO_BIN_EXE_rpc-attest-sidecar");
    let mut cmd = Command::new(bin);
    cmd.arg("--listen-addr")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream-url")
        .arg(args.upstream_url)
        .arg("--chain-id")
        .arg(args.chain_id.to_string())
        .arg("--dstack-endpoint")
        .arg(args.dstack_endpoint);
    // Simulator may not populate compose_hash; tests must keep booting.
    cmd.env("SIDECAR_ALLOW_EMPTY_COMPOSE_HASH", "true");
    cmd.env("RUST_LOG", "info");
    for (k, v) in args.extra_env {
        cmd.env(k, v);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn sidecar");

    // tracing_subscriber::fmt() writes to stdout by default. Capture both
    // streams so the test can see the boot-time `signing_pubkey = …` line
    // and so any stderr-level output (panics, allocator errors) isn't lost.
    let stdout = child.stdout.take().expect("sidecar stdout");
    let stderr = child.stderr.take().expect("sidecar stderr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_out = captured.clone();
    let cap_err = captured.clone();
    let join_out = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            cap_out.lock().unwrap().push(line);
        }
    });
    let join_err = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            cap_err.lock().unwrap().push(line);
        }
    });
    // Combine into a single join for the Drop impl below.
    let join = std::thread::spawn(move || {
        let _ = join_out.join();
        let _ = join_err.join();
    });

    // Wait up to 10s for `signing_pubkey = 0x...` to appear.
    let pubkey = match wait_for_pubkey(&captured, Duration::from_secs(10)) {
        Ok(p) => p,
        Err(e) => {
            let snapshot = captured.lock().unwrap().clone();
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "sidecar did not log signing_pubkey within 10s: {e}\n--- captured ---\n{}",
                snapshot.join("\n")
            );
        }
    };
    // The pubkey appears in logs BEFORE the listener binds (see main.rs flow:
    // info!(signing_pubkey) → TcpListener::bind). Wait until the port is
    // actually accepting connections so callers don't race the listener.
    if let Err(e) = wait_for_listener(port, Duration::from_secs(5)) {
        let snapshot = captured.lock().unwrap().clone();
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "sidecar listener on 127.0.0.1:{port} did not open: {e}\n--- captured ---\n{}",
            snapshot.join("\n")
        );
    }

    SidecarHandle {
        child,
        base_url: format!("http://127.0.0.1:{port}"),
        signing_pubkey: pubkey,
        chain_id: args.chain_id,
        stdout_join: Some(join),
        captured,
    }
}

/// Spawn a sidecar that is expected to FAIL boot (e.g. unreachable dstack).
/// Returns the captured stderr and the exit status.
pub fn spawn_sidecar_expect_fail(
    upstream_url: &str,
    chain_id: u64,
    dstack_endpoint: &Path,
    within: Duration,
) -> (Vec<String>, std::process::ExitStatus) {
    let port = ephemeral_port();
    let bin = env!("CARGO_BIN_EXE_rpc-attest-sidecar");
    let mut child = Command::new(bin)
        .arg("--listen-addr")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--upstream-url")
        .arg(upstream_url)
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .arg("--dstack-endpoint")
        .arg(dstack_endpoint)
        .env("SIDECAR_ALLOW_EMPTY_COMPOSE_HASH", "true")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sidecar");

    let stdout = child.stdout.take().expect("sidecar stdout");
    let stderr = child.stderr.take().expect("sidecar stderr");
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_out = captured.clone();
    let cap_err = captured.clone();
    let join_out = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            cap_out.lock().unwrap().push(line);
        }
    });
    let join_err = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            cap_err.lock().unwrap().push(line);
        }
    });
    let join = std::thread::spawn(move || {
        let _ = join_out.join();
        let _ = join_err.join();
    });

    let deadline = Instant::now() + within;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("sidecar did not exit within {within:?}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("waiting for sidecar: {e}"),
        }
    };
    let _ = join.join();
    let lines = captured.lock().unwrap().clone();
    (lines, status)
}

fn wait_for_pubkey(captured: &Mutex<Vec<String>>, max: Duration) -> TestResult<[u8; 32]> {
    let started = Instant::now();
    let re_needle = "signing_pubkey=";
    while started.elapsed() < max {
        let snapshot = captured.lock().unwrap().clone();
        for line in &snapshot {
            // Tracing default formats fields as `signing_pubkey=0xdead…` or
            // `signing_pubkey=\"0xdead…\"` depending on the formatter — accept both.
            if let Some(start) = line.find(re_needle) {
                let rest = &line[start + re_needle.len()..];
                let cleaned = rest.trim().trim_matches('"');
                let hex = cleaned
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("0x");
                if hex.len() == 64 {
                    let bytes = hex::decode(hex).map_err(to_err)?;
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&bytes);
                    return Ok(out);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("signing_pubkey not seen in sidecar logs".into())
}

// ===== HTTP client (to talk to the sidecar) =====

pub type Hyper = Client<HttpConnector, Full<Bytes>>;

pub fn http_client() -> Hyper {
    Client::builder(TokioExecutor::new()).build_http()
}

pub struct HttpResponse {
    pub status: hyper::StatusCode,
    pub headers: hyper::HeaderMap,
    pub body: Bytes,
}

pub async fn post_bytes(
    client: &Hyper,
    url: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> TestResult<HttpResponse> {
    let mut req = hyper::Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(Bytes::from(body))).map_err(to_err)?;
    let resp = client.request(req).await.map_err(to_err)?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.map_err(to_err)?.to_bytes();
    Ok(HttpResponse {
        status: parts.status,
        headers: parts.headers,
        body: bytes,
    })
}

pub async fn get(client: &Hyper, url: &str) -> TestResult<HttpResponse> {
    let req = hyper::Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Full::new(Bytes::new()))
        .map_err(to_err)?;
    let resp = client.request(req).await.map_err(to_err)?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.map_err(to_err)?.to_bytes();
    Ok(HttpResponse {
        status: parts.status,
        headers: parts.headers,
        body: bytes,
    })
}

// ===== Signature verification =====

pub fn build_pre_image(
    chain_id: u64,
    request_body: &[u8],
    response_body: &[u8],
    timestamp_ms: u64,
) -> [u8; 80] {
    let req_hash = sha2_256(request_body);
    let resp_hash = sha2_256(response_body);
    let mut buf = [0u8; 80];
    buf[0..8].copy_from_slice(&chain_id.to_le_bytes());
    buf[8..40].copy_from_slice(&req_hash);
    buf[40..72].copy_from_slice(&resp_hash);
    buf[72..80].copy_from_slice(&timestamp_ms.to_le_bytes());
    buf
}

pub fn sha2_256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn header_str<'a>(headers: &'a hyper::HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

pub fn decode_hex_0x(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("hex decode")
}

pub fn verify_signed_response(
    chain_id: u64,
    request_body: &[u8],
    resp: &HttpResponse,
) -> TestResult<()> {
    let sig_hex = header_str(&resp.headers, "vrpc-signature");
    let ts_hex = header_str(&resp.headers, "vrpc-timestamp");
    let pk_hex = header_str(&resp.headers, "vrpc-pubkey");
    if sig_hex.is_empty() || ts_hex.is_empty() || pk_hex.is_empty() {
        return Err(format!(
            "missing vRPC-* headers: sig={sig_hex} ts={ts_hex} pk={pk_hex}"
        ));
    }
    let sig_bytes = decode_hex_0x(sig_hex);
    let pk_bytes = decode_hex_0x(pk_hex);
    let ts_ms: u64 = ts_hex.parse().map_err(to_err)?;
    if sig_bytes.len() != 64 {
        return Err(format!("signature must be 64B, got {}", sig_bytes.len()));
    }
    if pk_bytes.len() != 32 {
        return Err(format!("pubkey must be 32B, got {}", pk_bytes.len()));
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pk_bytes);
    let mut sig64 = [0u8; 64];
    sig64.copy_from_slice(&sig_bytes);

    let pre = build_pre_image(chain_id, request_body, &resp.body, ts_ms);
    let vk = VerifyingKey::from_bytes(&pk32).map_err(to_err)?;
    vk.verify(&pre, &sig64.into()).map_err(to_err)?;
    Ok(())
}

// ===== Mock upstream =====

pub struct MockUpstream {
    pub url: String,
    pub state: Arc<MockState>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

#[derive(Default)]
pub struct MockState {
    pub received: Mutex<Vec<MockRequest>>,
    pub response: Mutex<MockResponse>,
    /// Per-connection `serve_connection` task handles. Collect these so
    /// `MockUpstream::drop` can best-effort wait for in-flight handlers to push
    /// to `received` before the test asserts on the vec — without this, tests
    /// that race the assertion against connection teardown sporadically see
    /// `received.len() == 0`.
    pub conn_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct MockRequest {
    pub method: hyper::Method,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

#[derive(Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl Default for MockResponse {
    fn default() -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"result\":\"0x1\",\"id\":1}"),
        }
    }
}

impl MockUpstream {
    pub async fn start() -> MockUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        let state = Arc::new(MockState::default());
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        let state_cl = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else { continue };
                        let state = state_cl.clone();
                        // Keep the per-connection handle so `Drop` can
                        // best-effort wait for in-flight handlers to push to
                        // `received` before the test reads it.
                        let handle = tokio::spawn(async move {
                            let _ = http1::Builder::new()
                                .serve_connection(
                                    TokioIo::new(stream),
                                    service_fn(move |req| {
                                        let state = state.clone();
                                        async move { handle(req, state).await }
                                    }),
                                )
                                .await;
                        });
                        state_cl.conn_handles.lock().unwrap().push(handle);
                    }
                }
            }
        });
        MockUpstream {
            url: format!("http://{addr}"),
            state,
            _shutdown: tx,
        }
    }

    pub fn received(&self) -> Vec<MockRequest> {
        self.state.received.lock().unwrap().clone()
    }

    pub fn set_response(&self, r: MockResponse) {
        *self.state.response.lock().unwrap() = r;
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        // Best-effort drain in-flight per-connection tasks so that the
        // test asserting on `received()` after the upstream drops sees every
        // recorded request. Bounded at 200ms — better to flake the assert
        // than hang the test process. After the timeout (or on a single-thread
        // runtime where we can't block_on), we abort the handles so the
        // runtime can tear them down cleanly.
        let mut handles: Vec<_> = std::mem::take(&mut *self.state.conn_handles.lock().unwrap());
        if handles.is_empty() {
            return;
        }
        let abort_all = |hs: &mut Vec<tokio::task::JoinHandle<()>>| {
            for h in hs.iter() {
                h.abort();
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
            {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        let timeout = tokio::time::sleep(Duration::from_millis(200));
                        tokio::pin!(timeout);
                        for h in handles.iter_mut() {
                            tokio::select! {
                                _ = h => {},
                                _ = &mut timeout => break,
                            }
                        }
                    });
                });
                abort_all(&mut handles);
            }
            _ => {
                // No runtime, or single-threaded runtime — can't safely
                // block_on here. Abort and let the runtime reap.
                abort_all(&mut handles);
            }
        }
    }
}

async fn handle(
    req: hyper::Request<Incoming>,
    state: Arc<MockState>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let headers: HashMap<String, String> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect();
    state.received.lock().unwrap().push(MockRequest {
        method: parts.method.clone(),
        uri: parts.uri.to_string(),
        headers,
        body: bytes,
    });
    let resp = state.response.lock().unwrap().clone();
    let mut builder = hyper::Response::builder().status(resp.status);
    for (k, v) in &resp.headers {
        builder = builder.header(k, v);
    }
    Ok(builder.body(Full::new(resp.body)).unwrap())
}
