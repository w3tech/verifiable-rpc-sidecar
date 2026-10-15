// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! RFC 9458 §4.3/§4.4 encapsulation for Ankr Confidential RPC, composed from
//! `hpke`, `hkdf` and `aes-gcm`. Pure crypto: no HTTP types.

use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use hpke::{
    kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _, OpModeR, Serializable,
};
use sha2::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

pub const RESPONSE_NONCE_LEN: usize = 32;

const HDR_LEN: usize = 7;
const ENC_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
const REQUEST_LABEL: &[u8] = b"message/bhttp request";
const RESPONSE_LABEL: &[u8] = b"message/bhttp response";

type PrivateKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;
type EncappedKey = <X25519HkdfSha256 as hpke::Kem>::EncappedKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("encapsulated message rejected")]
pub struct EnvelopeError;

trait Suite {
    type HpkeAead: hpke::aead::Aead;
    type Gcm: KeyInit + AeadInOut;
    const HDR: [u8; HDR_LEN];
    /// max(Nn, Nk) of the AEAD, RFC 9458 §4.4.
    const SECRET_LEN: usize;
}

struct ConfidentialSuite;

impl Suite for ConfidentialSuite {
    type HpkeAead = hpke::aead::AesGcm256;
    type Gcm = aes_gcm::Aes256Gcm;
    const HDR: [u8; HDR_LEN] = [0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x02];
    const SECRET_LEN: usize = 32;
}

type SealFn = fn(&[u8], &[u8], &mut Vec<u8>, usize) -> Result<(), EnvelopeError>;

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
    open::<ConfidentialSuite>(sk_r, body)
}

impl ResponseContext {
    pub fn seal(
        self,
        response_nonce: &[u8; RESPONSE_NONCE_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        self.seal_with_nonce(response_nonce, plaintext)
    }

    /// Seal `buf` = response_nonce ‖ plaintext into response_nonce ‖ ciphertext ‖ tag;
    /// on error `buf` is wiped.
    pub fn seal_in_place(self, buf: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        let sealed = self.seal_buf(buf);
        if sealed.is_err() {
            buf.zeroize();
        }
        sealed
    }

    fn seal_buf(&self, buf: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        let response_nonce = buf.get(..self.secret_len).ok_or(EnvelopeError)?;
        let mut salt = [0u8; ENC_LEN + 32];
        salt[..ENC_LEN].copy_from_slice(&self.enc);
        salt[ENC_LEN..ENC_LEN + self.secret_len].copy_from_slice(response_nonce);
        (self.seal)(
            &salt[..ENC_LEN + self.secret_len],
            &self.secret[..self.secret_len],
            buf,
            self.secret_len,
        )
    }

    fn seal_with_nonce(
        self,
        response_nonce: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError> {
        if response_nonce.len() != self.secret_len {
            return Err(EnvelopeError);
        }
        let mut out = Vec::with_capacity(self.secret_len + plaintext.len() + TAG_LEN);
        out.extend_from_slice(response_nonce);
        out.extend_from_slice(plaintext);
        self.seal_in_place(&mut out)?;
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
    let mut secret = Zeroizing::new([0u8; 32]);
    ctx.export(RESPONSE_LABEL, &mut secret[..S::SECRET_LEN])
        .map_err(|_| EnvelopeError)?;
    let plaintext = ctx.open(ct, b"").map_err(|_| EnvelopeError)?;

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
    buf: &mut Vec<u8>,
    offset: usize,
) -> Result<(), EnvelopeError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = Zeroizing::new([0u8; 32]);
    let key = &mut key[..<S::Gcm as aes_gcm::aead::KeySizeUser>::key_size()];
    hk.expand(b"key", key).map_err(|_| EnvelopeError)?;
    let mut nonce = Zeroizing::new([0u8; 12]);
    hk.expand(b"nonce", &mut nonce[..])
        .map_err(|_| EnvelopeError)?;
    let cipher = S::Gcm::new_from_slice(key).map_err(|_| EnvelopeError)?;
    let nonce = aes_gcm::aead::Nonce::<S::Gcm>::try_from(&nonce[..]).map_err(|_| EnvelopeError)?;
    let plaintext = buf.get_mut(offset..).ok_or(EnvelopeError)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, b"", InOutBuf::from(plaintext))
        .map_err(|_| EnvelopeError)?;
    buf.extend_from_slice(&tag);
    Ok(())
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

    struct RfcAppendixA;

    impl Suite for RfcAppendixA {
        type HpkeAead = hpke::aead::AesGcm128;
        type Gcm = aes_gcm::Aes128Gcm;
        const HDR: [u8; HDR_LEN] = [0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x01];
        const SECRET_LEN: usize = 16;
    }

    #[test]
    fn cfrg_vector_opens_and_exports() {
        // draft-irtf-cfrg-hpke test-vectors.json @ 5f503c564da00b0687b3de75f1dfbdfc4079ad31, mode 0, kem 32 / kdf 1 / aead 2
        let sk_r = key("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
        let pk_r = h("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
        let enc = h("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let aad = h("436f756e742d30");
        let ct = h(concat!(
            "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be99319",
            "80a41de125a925cdad859d5b7a"
        ));
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let exported = h("ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a");

        assert_eq!(public_key(&sk_r).unwrap().to_vec(), pk_r);
        let sk = PrivateKey::from_bytes(&sk_r).unwrap();
        let enc = EncappedKey::from_bytes(&enc).unwrap();
        let mut ctx = hpke::setup_receiver::<hpke::aead::AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &sk,
            &enc,
            &info,
        )
        .unwrap();
        assert_eq!(ctx.open(&ct, &aad).unwrap(), pt);
        let mut out = [0u8; 32];
        ctx.export(b"", &mut out).unwrap();
        assert_eq!(out.to_vec(), exported);
    }

    #[test]
    fn rfc9458_appendix_a_through_generic_framing() {
        let sk = key("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a");
        assert_eq!(
            public_key(&sk).unwrap().to_vec(),
            h("31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155")
        );
        let req = h(concat!(
            "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad1",
            "9dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e796",
            "5e7d86b83dd440b2c0185204b4d63525"
        ));
        let (pt, ctx) = open::<RfcAppendixA>(&sk, &req).unwrap();
        assert_eq!(pt, h("00034745540568747470730b6578616d706c652e636f6d012f"));
        assert_eq!(
            ctx.secret[..16].to_vec(),
            h("62d87a6ba569ee81014c2641f52bea36")
        );
        let res = ctx
            .seal_with_nonce(&h("c789e7151fcba46158ca84b04464910d"), &h("0140c8"))
            .unwrap();
        assert_eq!(
            res,
            h("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")
        );
        assert_eq!(open_request(&sk, &req).err(), Some(EnvelopeError));
    }

    #[test]
    fn every_pre_decapsulation_failure_is_the_same_error() {
        let v = vectors();
        let e = &v["envelopes"][0];
        let sk = key(e["skR"].as_str().unwrap());
        let good = h(e["encapsulated_request"].as_str().unwrap());
        let min = HDR_LEN + ENC_LEN + TAG_LEN;
        assert!(good.len() > min);

        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            good[..HDR_LEN].to_vec(),
            good[..min - 1].to_vec(),
            good[..min].to_vec(),
        ];
        for (i, b) in [(0, 0x01), (2, 0x21), (4, 0x02), (6, 0x01), (6, 0x03)] {
            let mut c = good.clone();
            c[i] = b;
            cases.push(c);
        }
        let mut zero_enc = good.clone();
        zero_enc[HDR_LEN..HDR_LEN + ENC_LEN].fill(0);
        cases.push(zero_enc);
        let mut low_order_enc = good.clone();
        low_order_enc[HDR_LEN..HDR_LEN + ENC_LEN].fill(0);
        low_order_enc[HDR_LEN] = 0x01;
        cases.push(low_order_enc);
        for i in [HDR_LEN, HDR_LEN + ENC_LEN, good.len() - 1] {
            let mut c = good.clone();
            c[i] ^= 0x01;
            cases.push(c);
        }

        assert_eq!(cases.len(), 14);
        for c in &cases {
            assert_eq!(open_request(&sk, c).err(), Some(EnvelopeError));
        }
        assert!(open_request(&sk, &good).is_ok());
    }

    #[test]
    fn go_vector_opens_request_and_reseals_response() {
        let v = vectors();
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
