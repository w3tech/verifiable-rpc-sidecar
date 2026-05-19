//! Per-response signing pipeline.
//!
//! The pre-image layout is the SPEC-04 canonical 80-byte fixed raw format:
//!
//! ```text
//! [0..8]   chain_id        u64, little-endian
//! [8..40]  request_hash    sha256(request_body)
//! [40..72] response_hash   sha256(response_body)
//! [72..80] timestamp_ms    u64, little-endian
//! ```
//!
//! `SigningState` holds the Ed25519 keypair derived from dstack-KMS at boot.
//! `ZeroizeOnDrop` on the inner key clears the secret when the last `Arc`
//! reference drops (e.g. when the server exits graceful shutdown).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};

pub const PRE_IMAGE_LEN: usize = 80;
pub const REQ_HASH_OFFSET: usize = 8;
pub const RESP_HASH_OFFSET: usize = 40;
pub const TIMESTAMP_OFFSET: usize = 72;

#[derive(Clone)]
pub struct SigningState {
    inner: Arc<SigningInner>,
}

struct SigningInner {
    signing_key: SigningKey,
    chain_id: u64,
}

#[derive(Debug, Clone)]
pub struct SignedResponse {
    pub signature: [u8; 64],
    pub timestamp_ms: u64,
    pub pubkey: [u8; 32],
}

impl SignedResponse {
    pub fn signature_hex(&self) -> String {
        prefixed_hex(&self.signature)
    }

    pub fn pubkey_hex(&self) -> String {
        prefixed_hex(&self.pubkey)
    }
}

impl SigningState {
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH], chain_id: u64) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        Self {
            inner: Arc::new(SigningInner {
                signing_key,
                chain_id,
            }),
        }
    }

    pub fn from_dstack_bytes(bytes: &[u8], chain_id: u64) -> Result<Self> {
        // Reject any length other than exactly 32 bytes — silently truncating
        // longer HKDF output would defeat the C5 key-derivation-path guarantees
        // (two derivation paths sharing a 32-byte prefix could collide). See
        // REVIEW.md CR-01.
        if bytes.len() != SECRET_KEY_LENGTH {
            bail!(
                "dstack key was {} bytes, expected exactly {SECRET_KEY_LENGTH}",
                bytes.len()
            );
        }
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        seed.copy_from_slice(bytes);
        Ok(Self::from_seed(seed, chain_id))
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.inner.signing_key.verifying_key().to_bytes()
    }

    pub fn pubkey_hex(&self) -> String {
        prefixed_hex(&self.pubkey_bytes())
    }

    pub fn chain_id(&self) -> u64 {
        self.inner.chain_id
    }

    /// Sign a request/response pair. `timestamp_ms` is captured from the system
    /// clock — the server only emits the value; client-side replay-window
    /// enforcement lives in the v3 verifier SDK per SPEC-07.
    ///
    /// Returns `Err` if the system clock is unusable (before UNIX_EPOCH or past
    /// year 2554). Per CR-02, refusing to sign is preferred over emitting a
    /// signed `vRPC-Timestamp: 0` header that bypasses client-side replay
    /// windows.
    pub fn sign(&self, request_body: &[u8], response_body: &[u8]) -> Result<SignedResponse> {
        let ts_ms = now_ms()?;
        Ok(self.sign_with_timestamp(request_body, response_body, ts_ms))
    }

    pub fn sign_with_timestamp(
        &self,
        request_body: &[u8],
        response_body: &[u8],
        timestamp_ms: u64,
    ) -> SignedResponse {
        let req_hash = sha256(request_body);
        let resp_hash = sha256(response_body);
        let pre_image = build_pre_image(self.inner.chain_id, &req_hash, &resp_hash, timestamp_ms);
        let signature = self.inner.signing_key.sign(&pre_image).to_bytes();
        SignedResponse {
            signature,
            timestamp_ms,
            pubkey: self.pubkey_bytes(),
        }
    }
}

/// Build the SPEC-04 canonical 80-byte pre-image.
pub fn build_pre_image(
    chain_id: u64,
    request_hash: &[u8; 32],
    response_hash: &[u8; 32],
    timestamp_ms: u64,
) -> [u8; PRE_IMAGE_LEN] {
    let mut buf = [0u8; PRE_IMAGE_LEN];
    buf[0..REQ_HASH_OFFSET].copy_from_slice(&chain_id.to_le_bytes());
    buf[REQ_HASH_OFFSET..RESP_HASH_OFFSET].copy_from_slice(request_hash);
    buf[RESP_HASH_OFFSET..TIMESTAMP_OFFSET].copy_from_slice(response_hash);
    buf[TIMESTAMP_OFFSET..PRE_IMAGE_LEN].copy_from_slice(&timestamp_ms.to_le_bytes());
    buf
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn prefixed_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

fn now_ms() -> Result<u64> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    u64::try_from(d.as_millis()).context("clock overflow > u64 ms")
}

/// Parse chain id from CLI/env input. Honours the doc-comment contract on
/// `Config::chain_id`: `0x`/`0X`-prefixed strings parse as hex, bare numerics
/// parse as decimal. See WR-01 — silent reinterpretation of decimal `137` as
/// hex `0x137` is a silently-catastrophic operator footgun.
pub fn parse_chain_id_hex(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).with_context(|| format!("invalid chain_id hex: {s:?}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("invalid chain_id decimal: {s:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    /// Canonical seed used across tests so they exercise a deterministic key.
    const TEST_SEED: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, //
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, //
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, //
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    ];

    #[test]
    fn pre_image_layout_is_byte_exact() {
        let chain_id: u64 = 0x1122334455667788;
        let req_hash: [u8; 32] = [0xaa; 32];
        let resp_hash: [u8; 32] = [0xbb; 32];
        let timestamp_ms: u64 = 0x9988_7766_5544_3322;
        let pre = build_pre_image(chain_id, &req_hash, &resp_hash, timestamp_ms);

        assert_eq!(pre.len(), 80);
        // chain_id (8B LE)
        assert_eq!(
            &pre[0..8],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        // request_hash (32B)
        assert!(pre[8..40].iter().all(|&b| b == 0xaa));
        // response_hash (32B)
        assert!(pre[40..72].iter().all(|&b| b == 0xbb));
        // timestamp_ms (8B LE)
        assert_eq!(
            &pre[72..80],
            &[0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]
        );
    }

    #[test]
    fn sha256_matches_known_value() {
        // sha256("") == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = sha256(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sign_verify_roundtrip_passes_for_intact_body() {
        let state = SigningState::from_seed(TEST_SEED, 1);
        let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
        let resp = br#"{"jsonrpc":"2.0","result":"0x12345","id":1}"#;

        let signed = state.sign_with_timestamp(req, resp, 1_700_000_000_000);
        let pre = build_pre_image(1, &sha256(req), &sha256(resp), 1_700_000_000_000);

        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        vk.verify(&pre, &signed.signature.into())
            .expect("intact body must verify");
    }

    #[test]
    fn sign_verify_fails_when_response_body_is_tampered() {
        let state = SigningState::from_seed(TEST_SEED, 1);
        let req = b"req";
        let resp = b"resp";
        let mut tampered = resp.to_vec();
        tampered[0] ^= 0x01;

        let signed = state.sign_with_timestamp(req, resp, 42);
        let pre = build_pre_image(1, &sha256(req), &sha256(&tampered), 42);

        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        assert!(
            vk.verify(&pre, &signed.signature.into()).is_err(),
            "tampered response body must not verify"
        );
    }

    #[test]
    fn sign_treats_batch_and_single_uniformly() {
        let state = SigningState::from_seed(TEST_SEED, 137);
        let req =
            br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#;
        let resp = br#"[{"jsonrpc":"2.0","result":1,"id":1},{"jsonrpc":"2.0","result":2,"id":2}]"#;
        let signed = state.sign_with_timestamp(req, resp, 99);
        let pre = build_pre_image(137, &sha256(req), &sha256(resp), 99);
        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        vk.verify(&pre, &signed.signature.into())
            .expect("batch JSON-RPC must sign and verify the same way as single calls");
    }

    #[test]
    fn pubkey_hex_is_0x_prefixed_lowercase_64_chars() {
        let state = SigningState::from_seed(TEST_SEED, 1);
        let hex = state.pubkey_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 64);
        assert!(hex[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn signature_hex_is_0x_prefixed_64_byte_hex() {
        let state = SigningState::from_seed(TEST_SEED, 1);
        let signed = state.sign_with_timestamp(b"req", b"resp", 1);
        let hex = signed.signature_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 128);
    }

    #[test]
    fn from_dstack_bytes_accepts_exact_32_bytes() {
        let s = SigningState::from_dstack_bytes(&TEST_SEED, 1).unwrap();
        assert_eq!(s.pubkey_bytes().len(), 32);
    }

    #[test]
    fn from_dstack_bytes_rejects_non_32_byte_input() {
        // Reject longer input — silent truncation would defeat C5 (see CR-01).
        let mut long = TEST_SEED.to_vec();
        long.extend_from_slice(&[0xcc; 16]);
        assert!(SigningState::from_dstack_bytes(&long, 1).is_err());
        // Reject shorter input too (covered separately below, but assert here
        // for symmetry).
        assert!(SigningState::from_dstack_bytes(&TEST_SEED[..31], 1).is_err());
    }

    #[test]
    fn from_dstack_bytes_rejects_short_input() {
        assert!(SigningState::from_dstack_bytes(&[0u8; 16], 1).is_err());
    }

    #[test]
    fn now_ms_returns_plausible_unix_millis() {
        // CR-02: now_ms must succeed on a working clock and return a value
        // within a sane bound (after 2020-01-01, before year 2554).
        let ts = now_ms().expect("system clock must be usable in tests");
        assert!(ts > 1_577_836_800_000, "now_ms = {ts} looks too old");
    }

    #[test]
    fn sign_returns_ok_when_clock_is_usable() {
        // CR-02: sign now returns Result; happy path must yield Ok.
        let state = SigningState::from_seed(TEST_SEED, 1);
        let signed = state
            .sign(b"req", b"resp")
            .expect("sign must succeed with a usable clock");
        assert_eq!(signed.signature.len(), 64);
    }

    #[test]
    fn parse_chain_id_hex_distinguishes_decimal_and_hex() {
        // WR-01: bare numerics are decimal, 0x-prefixed are hex.
        assert_eq!(parse_chain_id_hex("0x1").unwrap(), 1);
        assert_eq!(parse_chain_id_hex("1").unwrap(), 1);
        assert_eq!(parse_chain_id_hex("137").unwrap(), 137);
        assert_eq!(parse_chain_id_hex("0x89").unwrap(), 137);
        assert_eq!(parse_chain_id_hex("0X89").unwrap(), 137);
        assert_eq!(parse_chain_id_hex("56").unwrap(), 56);
        assert_eq!(parse_chain_id_hex("0x38").unwrap(), 56);
        assert!(parse_chain_id_hex("zz").is_err());
        // Bare "ff" is no longer hex — it's invalid decimal.
        assert!(parse_chain_id_hex("ff").is_err());
    }
}
