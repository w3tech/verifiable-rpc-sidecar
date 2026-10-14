// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! RFC 9458 §4.3/§4.4 encapsulation for Ankr Confidential RPC, composed from
//! `hpke`, `hkdf` and `aes-gcm`. Pure crypto: no HTTP types.

use aes_gcm::aead::{Aead as _, KeyInit};
use hkdf::Hkdf;
use hpke::{
    kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _, OpModeR, Serializable,
};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const RESPONSE_NONCE_LEN: usize = 32;

const HDR_LEN: usize = 7;
const ENC_LEN: usize = 32;
const TAG_LEN: usize = 16;
const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";

type PrivateKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;
type EncappedKey = <X25519HkdfSha256 as hpke::Kem>::EncappedKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("encapsulated message rejected")]
pub struct EnvelopeError;

trait Suite {
    type HpkeAead: hpke::aead::Aead;
    type Gcm: KeyInit + aes_gcm::aead::Aead;
    const HDR: [u8; HDR_LEN];
    /// max(Nn, Nk) of the AEAD, RFC 9458 §4.4.
    const SECRET_LEN: usize;
}

struct Contract;

impl Suite for Contract {
    type HpkeAead = hpke::aead::AesGcm256;
    type Gcm = aes_gcm::Aes256Gcm;
    const HDR: [u8; HDR_LEN] = [0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02];
    const SECRET_LEN: usize = 32;
}

type SealFn = fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, EnvelopeError>;

pub struct ResponseContext {
    enc: [u8; ENC_LEN],
    secret: Zeroizing<[u8; 32]>,
    secret_len: usize,
    seal: SealFn,
}

pub fn public_key(sk_r: &[u8; 32]) -> Result<[u8; 32], EnvelopeError> {
    let sk = PrivateKey::from_bytes(sk_r).map_err(|_| EnvelopeError)?;
    let pk = X25519HkdfSha256::sk_to_pk(&sk).to_bytes();
    pk.as_slice().try_into().map_err(|_| EnvelopeError)
}

pub fn open_request(
    sk_r: &[u8; 32],
    body: &[u8],
) -> Result<(Vec<u8>, ResponseContext), EnvelopeError> {
    open::<Contract>(sk_r, body)
}

impl ResponseContext {
    pub fn seal(
        self,
        response_nonce: &[u8; RESPONSE_NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_with_nonce(response_nonce, plaintext)
    }

    fn seal_with_nonce(
        self,
        response_nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if response_nonce.len() != self.secret_len {
            return Err(EnvelopeError);
        }
        let mut salt = [0u8; ENC_LEN + 32];
        salt[..ENC_LEN].copy_from_slice(&self.enc);
        salt[ENC_LEN..ENC_LEN + self.secret_len].copy_from_slice(response_nonce);
        let ct = (self.seal)(
            &salt[..ENC_LEN + self.secret_len],
            &self.secret[..self.secret_len],
            plaintext,
        )?;
        let mut out = Vec::with_capacity(self.secret_len + ct.len());
        out.extend_from_slice(response_nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

fn open<S: Suite>(
    sk_r: &[u8; 32],
    body: &[u8],
) -> Result<(Vec<u8>, ResponseContext), EnvelopeError> {
    // The header is checked before any DH so an unsupported suite costs nothing.
    if body.len() < HDR_LEN + ENC_LEN + TAG_LEN || body[..HDR_LEN] != S::HDR {
        return Err(EnvelopeError);
    }
    let (enc_bytes, ct) = body[HDR_LEN..].split_at(ENC_LEN);
    let mut info = [0u8; REQUEST_LABEL.len() + 1 + HDR_LEN];
    info[..REQUEST_LABEL.len()].copy_from_slice(REQUEST_LABEL);
    info[REQUEST_LABEL.len() + 1..].copy_from_slice(&S::HDR);

    let sk = PrivateKey::from_bytes(sk_r).map_err(|_| EnvelopeError)?;
    let enc = EncappedKey::from_bytes(enc_bytes).map_err(|_| EnvelopeError)?;
    let mut ctx = hpke::setup_receiver::<S::HpkeAead, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        &info,
    )
    .map_err(|_| EnvelopeError)?;
    let plaintext = ctx.open(ct, b"").map_err(|_| EnvelopeError)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    ctx.export(RESPONSE_LABEL, &mut secret[..S::SECRET_LEN])
        .map_err(|_| EnvelopeError)?;

    let mut enc_arr = [0u8; ENC_LEN];
    enc_arr.copy_from_slice(enc_bytes);
    Ok((
        plaintext,
        ResponseContext {
            enc: enc_arr,
            secret,
            secret_len: S::SECRET_LEN,
            seal: seal_response::<S>,
        },
    ))
}

fn seal_response<S: Suite>(
    salt: &[u8],
    secret: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = Zeroizing::new([0u8; 32]);
    let key = &mut key[..<S::Gcm as aes_gcm::aead::KeySizeUser>::key_size()];
    hk.expand(b"key", key).map_err(|_| EnvelopeError)?;
    let mut nonce = Zeroizing::new([0u8; 12]);
    hk.expand(b"nonce", &mut nonce[..])
        .map_err(|_| EnvelopeError)?;
    let cipher = S::Gcm::new_from_slice(key).map_err(|_| EnvelopeError)?;
    let nonce = aes_gcm::aead::Nonce::<S::Gcm>::try_from(&nonce[..]).map_err(|_| EnvelopeError)?;
    cipher.encrypt(&nonce, plaintext).map_err(|_| EnvelopeError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn key(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/confidential.json")).unwrap()
    }

    #[test]
    fn go_vector_opens_request_and_reseals_response() {
        let v = vectors();
        assert_eq!(v["contract_version"], "0.4");
        for e in v["envelopes"].as_array().unwrap() {
            let s = |k: &str| h(e[k].as_str().unwrap());
            let sk = key(e["skR"].as_str().unwrap());
            assert_eq!(public_key(&sk).unwrap().to_vec(), s("pkR"));
            let (pt, ctx) = open_request(&sk, &s("encapsulated_request")).unwrap();
            assert_eq!(pt, s("bhttp_request"));
            assert_eq!(ctx.secret.to_vec(), s("export_secret"));

            let m = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(&pt[..])).unwrap();
            let r = &e["request"];
            assert_eq!(
                m.control().method(),
                Some(r["method"].as_str().unwrap().as_bytes())
            );
            assert_eq!(
                m.control().path(),
                Some(r["path"].as_str().unwrap().as_bytes())
            );
            let ct = r["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == "content-type")
                .unwrap();
            assert_eq!(
                m.header().get(b"content-type"),
                Some(ct["value"].as_str().unwrap().as_bytes())
            );
            assert_eq!(m.content(), r["body"].as_str().unwrap().as_bytes());

            let resp = &e["response"];
            let mut out = bhttp::Message::response(
                bhttp::StatusCode::try_from(resp["status"].as_u64().unwrap() as u16).unwrap(),
            );
            for f in resp["fields"].as_array().unwrap() {
                out.put_header(f["name"].as_str().unwrap(), f["value"].as_str().unwrap());
            }
            out.write_content(resp["body"].as_str().unwrap());
            let mut bhttp_response = Vec::new();
            out.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_response)
                .unwrap();
            assert_eq!(bhttp_response, s("bhttp_response"));

            let nonce: [u8; RESPONSE_NONCE_LEN] = s("response_nonce").try_into().unwrap();
            assert_eq!(
                ctx.seal(&nonce, &bhttp_response).ok(),
                Some(s("encapsulated_response"))
            );
        }
    }
}
