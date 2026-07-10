// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! Per-response signing pipeline.
//!
//! The pre-image layout is the canonical 104-byte fixed raw format:
//!
//! ```text
//! [0..32]   chain_id_hash   sha256(utf8(chain_id))
//! [32..64]  request_hash    sha256(request_body)
//! [64..96]  response_hash   sha256(response_body)
//! [96..104] timestamp_ms    u64, little-endian
//! ```
//!
//! The chain id is an opaque string — `"42161"`, `"0x89"`, TON's `"-239"`, and
//! Stellar's network id (a 64-char hex string) are all just strings, never
//! parsed numerically. Two
//! distinct strings hash to distinct 32-byte slots, so a signature produced
//! for chain A can never verify under chain B's id.
//!
//! Per-chain key separation (why key derivation stays UNCHANGED): the dstack
//! `get_key(key_path = "rpc-sign/v1", purpose)` call does not include the
//! chain id today and intentionally stays that way. Separation holds because
//! (a) each app has its own dstack KMS root, and (b) `sha256(utf8(chain_id))`
//! is bound into every pre-image, so cross-chain signature reuse is
//! cryptographically excluded. Including the chain id in the key path is a
//! deferred design question, not needed for this guarantee.
//!
//! `SigningState` holds the Ed25519 keypair derived from dstack-KMS at boot.
//! `ZeroizeOnDrop` on the inner key clears the secret when the last `Arc`
//! reference drops (e.g. when the server exits graceful shutdown).
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};

use crate::util::prefixed_hex;

pub const PRE_IMAGE_LEN: usize = 104;
pub const REQ_HASH_OFFSET: usize = 32;
pub const RESP_HASH_OFFSET: usize = 64;
pub const TIMESTAMP_OFFSET: usize = 96;

/// Maximum byte length accepted for a chain id.
const CHAIN_ID_MAX_LEN: usize = 64;

/// Validate a chain id from CLI/env input.
///
/// Chain ids are opaque strings — no numeric parsing. They must be non-empty
/// after trimming, at most 64 bytes, and consist solely of printable ASCII
/// with no whitespace (`:`, `-`, `.`, `_`, `/` are all fine, covering ids like
/// TON's global id `-239`, Stellar's network id (sha256 of the passphrase, a
/// 64-char hex string), and numeric-looking ids like `42161` or `0x89`).
/// Violations abort boot with an error naming
/// the failed constraint.
pub fn validate_chain_id(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("chain_id must not be empty"));
    }
    if s.len() > CHAIN_ID_MAX_LEN {
        return Err(anyhow!(
            "chain_id {s:?} is {} bytes, exceeds the {CHAIN_ID_MAX_LEN}-byte limit",
            s.len()
        ));
    }
    if let Some(c) = s.chars().find(|c| !c.is_ascii_graphic()) {
        return Err(anyhow!(
            "chain_id {s:?} contains non-printable-ASCII or whitespace character {c:?}"
        ));
    }
    Ok(s.to_owned())
}

#[derive(Clone)]
pub struct SigningState {
    inner: Arc<SigningInner>,
}

struct SigningInner {
    signing_key: SigningKey,
    chain_id: String,
    /// `sha256(utf8(chain_id))` resolved once at construction — the sign path
    /// does zero per-request chain-id hashing.
    chain_id_hash: [u8; 32],
    /// Pubkey hex is hot — every signed response renders it into the
    /// `vRPC-Pubkey` header. Pre-compute once at construction and lend out
    /// `&str` to all callers (proxy, attestation, startup logging).
    pubkey_hex: String,
}

#[derive(Debug, Clone)]
pub struct SignedResponse {
    pub signature: [u8; 64],
    pub timestamp_ms: u64,
    pub pubkey: [u8; 32],
    /// Cached `0x`-prefixed pubkey hex string, populated by `SigningState::sign`
    /// from `SigningInner::pubkey_hex`. Lets the proxy emit `vRPC-Pubkey`
    /// without re-rendering 32 bytes on every signed response.
    pub pubkey_hex: String,
}

impl SignedResponse {
    pub fn signature_hex(&self) -> String {
        prefixed_hex(&self.signature)
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }
}

impl SigningState {
    pub fn from_seed(seed: [u8; SECRET_KEY_LENGTH], chain_id: impl Into<String>) -> Self {
        let chain_id = chain_id.into();
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey_hex = prefixed_hex(signing_key.verifying_key().as_bytes());
        let chain_id_hash = sha256(chain_id.as_bytes());
        Self {
            inner: Arc::new(SigningInner {
                signing_key,
                chain_id,
                chain_id_hash,
                pubkey_hex,
            }),
        }
    }

    pub fn from_dstack_bytes(bytes: &[u8], chain_id: impl Into<String>) -> Result<Self> {
        // Reject any length other than exactly 32 bytes — silently truncating
        // longer HKDF output would defeat the key-derivation-path guarantees
        // (two derivation paths sharing a 32-byte prefix could collide).
        let seed: [u8; SECRET_KEY_LENGTH] = bytes.try_into().map_err(|_| {
            anyhow!(
                "dstack key was {} bytes, expected exactly {SECRET_KEY_LENGTH}",
                bytes.len()
            )
        })?;
        Ok(Self::from_seed(seed, chain_id))
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.inner.signing_key.verifying_key().to_bytes()
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.inner.pubkey_hex
    }

    pub fn chain_id(&self) -> &str {
        &self.inner.chain_id
    }

    /// Sign a request/response pair. `timestamp_ms` is captured from the system
    /// clock — the server only emits the value; client-side replay-window
    /// enforcement lives in the verifier SDK.
    ///
    /// Returns `Err` if the system clock is unusable (before UNIX_EPOCH or past
    /// year 2554). Refusing to sign is preferred over emitting a signed
    /// `vRPC-Timestamp: 0` header that bypasses client-side replay windows.
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
        let pre_image = build_pre_image(
            &self.inner.chain_id_hash,
            &req_hash,
            &resp_hash,
            timestamp_ms,
        );
        let signature = self.inner.signing_key.sign(&pre_image).to_bytes();
        SignedResponse {
            signature,
            timestamp_ms,
            pubkey: self.pubkey_bytes(),
            pubkey_hex: self.inner.pubkey_hex.clone(),
        }
    }
}

/// Build the canonical 104-byte pre-image.
///
/// Layout: `chain_id_hash` at `[0..32]`, `request_hash` at `[32..64]`,
/// `response_hash` at `[64..96]`, `timestamp_ms` u64 little-endian at
/// `[96..104]`. The caller passes `sha256(utf8(chain_id))` — the builder
/// does not hash.
pub fn build_pre_image(
    chain_id_hash: &[u8; 32],
    request_hash: &[u8; 32],
    response_hash: &[u8; 32],
    timestamp_ms: u64,
) -> [u8; PRE_IMAGE_LEN] {
    let mut buf = [0u8; PRE_IMAGE_LEN];
    buf[0..REQ_HASH_OFFSET].copy_from_slice(chain_id_hash);
    buf[REQ_HASH_OFFSET..RESP_HASH_OFFSET].copy_from_slice(request_hash);
    buf[RESP_HASH_OFFSET..TIMESTAMP_OFFSET].copy_from_slice(response_hash);
    buf[TIMESTAMP_OFFSET..PRE_IMAGE_LEN].copy_from_slice(&timestamp_ms.to_le_bytes());
    buf
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn now_ms() -> Result<u64> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    u64::try_from(d.as_millis()).context("clock overflow > u64 ms")
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
        let chain_hash: [u8; 32] = [0xcc; 32];
        let req_hash: [u8; 32] = [0xaa; 32];
        let resp_hash: [u8; 32] = [0xbb; 32];
        let timestamp_ms: u64 = 0x9988_7766_5544_3322;
        let pre = build_pre_image(&chain_hash, &req_hash, &resp_hash, timestamp_ms);

        assert_eq!(pre.len(), 104);
        // chain_id hash (32B)
        assert!(pre[0..32].iter().all(|&b| b == 0xcc));
        // request_hash (32B)
        assert!(pre[32..64].iter().all(|&b| b == 0xaa));
        // response_hash (32B)
        assert!(pre[64..96].iter().all(|&b| b == 0xbb));
        // timestamp_ms (8B LE)
        assert_eq!(
            &pre[96..104],
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
    fn chain_id_hash_matches_known_answer() {
        // Known-answer vectors the verifier SDK mirror must reproduce.
        assert_eq!(
            hex::encode(sha256(b"-239")),
            "7d1a0b60d68a1efc2e01df13132034d669b2ce5b05c8bf6d4ae6322e810c5659"
        );
        assert_eq!(
            hex::encode(sha256(
                b"7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
            )),
            "dd4a5b7a84a301d6a8db49bff6877b3ef17b03d7afd19302fab324d1b7b4e1f7"
        );
        // Numeric-looking ids are hashed as strings too — never parsed.
        assert_eq!(
            hex::encode(sha256(b"42161")),
            "936a20303015aca26be61e6782c83b1de6b4b25f3dbdf555a97d85e0477a53a9"
        );
    }

    #[test]
    fn sign_verify_roundtrip_passes_for_intact_body() {
        let state = SigningState::from_seed(TEST_SEED, "1");
        let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
        let resp = br#"{"jsonrpc":"2.0","result":"0x12345","id":1}"#;

        let signed = state.sign_with_timestamp(req, resp, 1_700_000_000_000);
        let pre = build_pre_image(
            &sha256(b"1"),
            &sha256(req),
            &sha256(resp),
            1_700_000_000_000,
        );

        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        vk.verify(&pre, &signed.signature.into())
            .expect("intact body must verify");
    }

    #[test]
    fn sign_verify_fails_when_response_body_is_tampered() {
        let state = SigningState::from_seed(TEST_SEED, "1");
        let req = b"req";
        let resp = b"resp";
        let mut tampered = resp.to_vec();
        tampered[0] ^= 0x01;

        let signed = state.sign_with_timestamp(req, resp, 42);
        let pre = build_pre_image(&sha256(b"1"), &sha256(req), &sha256(&tampered), 42);

        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        assert!(
            vk.verify(&pre, &signed.signature.into()).is_err(),
            "tampered response body must not verify"
        );
    }

    #[test]
    fn sign_with_caip2_style_chain_id_verifies() {
        let state = SigningState::from_seed(TEST_SEED, "-239");
        let req = br#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
        let resp = br#"{"jsonrpc":"2.0","result":"0x12345","id":1}"#;

        let signed = state.sign_with_timestamp(req, resp, 1_700_000_000_000);
        let pre = build_pre_image(
            &sha256(b"-239"),
            &sha256(req),
            &sha256(resp),
            1_700_000_000_000,
        );

        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        vk.verify(&pre, &signed.signature.into())
            .expect("CAIP-2 style chain id must verify");
    }

    #[test]
    fn distinct_chain_ids_never_cross_verify() {
        // A signature produced under chain id "137" must NOT verify against a
        // pre-image built for a different chain id from the same inputs.
        let req = b"req";
        let resp = b"resp";
        let ts: u64 = 1_700_000_000_000;

        let state = SigningState::from_seed(TEST_SEED, "137");
        let signed = state.sign_with_timestamp(req, resp, ts);

        let other = build_pre_image(&sha256(b"0x89"), &sha256(req), &sha256(resp), ts);
        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        assert!(
            vk.verify(&other, &signed.signature.into()).is_err(),
            "signature must not verify under a different chain id string"
        );
    }

    #[test]
    fn sign_treats_batch_and_single_uniformly() {
        let state = SigningState::from_seed(TEST_SEED, "137");
        let req =
            br#"[{"jsonrpc":"2.0","method":"a","id":1},{"jsonrpc":"2.0","method":"b","id":2}]"#;
        let resp = br#"[{"jsonrpc":"2.0","result":1,"id":1},{"jsonrpc":"2.0","result":2,"id":2}]"#;
        let signed = state.sign_with_timestamp(req, resp, 99);
        let pre = build_pre_image(&sha256(b"137"), &sha256(req), &sha256(resp), 99);
        let vk = VerifyingKey::from_bytes(&signed.pubkey).unwrap();
        vk.verify(&pre, &signed.signature.into())
            .expect("batch JSON-RPC must sign and verify the same way as single calls");
    }

    #[test]
    fn pubkey_hex_is_0x_prefixed_lowercase_64_chars() {
        let state = SigningState::from_seed(TEST_SEED, "1");
        let hex = state.pubkey_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 64);
        assert!(hex[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn pubkey_hex_is_cached_and_matches_pubkey_bytes() {
        // pubkey_hex lends from a string cached at construction;
        // verify two calls return identical strings and the hex actually
        // matches `pubkey_bytes()` (i.e. the cache is correct, not stale).
        let state = SigningState::from_seed(TEST_SEED, "1");
        let a = state.pubkey_hex().to_owned();
        let b = state.pubkey_hex().to_owned();
        assert_eq!(a, b, "pubkey_hex must be stable across calls");
        let expected = format!("0x{}", hex::encode(state.pubkey_bytes()));
        assert_eq!(a, expected, "cached pubkey_hex must match pubkey_bytes");
    }

    #[test]
    fn signed_response_carries_cached_pubkey_hex() {
        // Every SignedResponse should already include the rendered hex
        // so the proxy can emit `vRPC-Pubkey` without re-allocating.
        let state = SigningState::from_seed(TEST_SEED, "1");
        let signed = state.sign_with_timestamp(b"req", b"resp", 1);
        assert_eq!(signed.pubkey_hex(), state.pubkey_hex());
    }

    #[test]
    fn signature_hex_is_0x_prefixed_64_byte_hex() {
        let state = SigningState::from_seed(TEST_SEED, "1");
        let signed = state.sign_with_timestamp(b"req", b"resp", 1);
        let hex = signed.signature_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 2 + 128);
    }

    #[test]
    fn from_dstack_bytes_accepts_exact_32_bytes() {
        let s = SigningState::from_dstack_bytes(&TEST_SEED, "1").unwrap();
        assert_eq!(s.pubkey_bytes().len(), 32);
    }

    #[test]
    fn from_dstack_bytes_rejects_non_32_byte_input() {
        // Reject longer input — silent truncation would defeat the
        // key-derivation-path uniqueness guarantee.
        let mut long = TEST_SEED.to_vec();
        long.extend_from_slice(&[0xcc; 16]);
        assert!(SigningState::from_dstack_bytes(&long, "1").is_err());
        // Reject shorter input too (covered separately below, but assert here
        // for symmetry).
        assert!(SigningState::from_dstack_bytes(&TEST_SEED[..31], "1").is_err());
    }

    #[test]
    fn from_dstack_bytes_rejects_short_input() {
        assert!(SigningState::from_dstack_bytes(&[0u8; 16], "1").is_err());
    }

    #[test]
    fn now_ms_returns_plausible_unix_millis() {
        // now_ms must succeed on a working clock and return a value
        // within a sane bound (after 2020-01-01, before year 2554).
        let ts = now_ms().expect("system clock must be usable in tests");
        assert!(ts > 1_577_836_800_000, "now_ms = {ts} looks too old");
    }

    #[test]
    fn sign_returns_ok_when_clock_is_usable() {
        // sign returns Result; happy path must yield Ok.
        let state = SigningState::from_seed(TEST_SEED, "1");
        let signed = state
            .sign(b"req", b"resp")
            .expect("sign must succeed with a usable clock");
        assert_eq!(signed.signature.len(), 64);
    }

    #[test]
    fn validate_chain_id_accepts_valid_ids() {
        assert_eq!(validate_chain_id("42161").unwrap(), "42161");
        assert_eq!(validate_chain_id("0x89").unwrap(), "0x89");
        assert_eq!(validate_chain_id("-239").unwrap(), "-239");
        // Stellar network id — 64-byte hex, exactly at the length limit.
        let stellar = "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979";
        assert_eq!(validate_chain_id(stellar).unwrap(), stellar);
        // Surrounding whitespace is trimmed, not rejected.
        assert_eq!(validate_chain_id(" 137 ").unwrap(), "137");
        // 64-byte boundary is accepted.
        let max = "x".repeat(64);
        assert_eq!(validate_chain_id(&max).unwrap(), max);
    }

    #[test]
    fn validate_chain_id_rejects_invalid_ids() {
        // Empty (before or after trim) is rejected.
        assert!(validate_chain_id("").is_err());
        assert!(validate_chain_id(" ").is_err());
        // Internal whitespace is rejected.
        assert!(validate_chain_id("a b").is_err());
        assert!(validate_chain_id("a\tb").is_err());
        // 65 bytes exceeds the limit.
        assert!(validate_chain_id(&"x".repeat(65)).is_err());
        // Non-ASCII is rejected.
        assert!(validate_chain_id("cépas").is_err());
        // Non-printable control characters are rejected.
        assert!(validate_chain_id("a\u{7f}b").is_err());
    }
}
