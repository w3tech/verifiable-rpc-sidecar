// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! The inner BHTTP request and response of `/confidential`: decoding rules, batch count, encoding.

use std::io::Cursor;

use axum::http::{HeaderValue, Method};
use bytes::Bytes;
use zeroize::Zeroize as _;

use super::InnerError;
use crate::envelope::{RESPONSE_NONCE_LEN, TAG_LEN};
use crate::proxy::MAX_PATH_AND_QUERY;

pub(super) struct InnerRequest {
    pub(super) method: Method,
    pub(super) path_and_query: Vec<u8>,
    pub(super) content_type: Option<HeaderValue>,
    pub(super) accept: Vec<HeaderValue>,
    pub(super) body: Vec<u8>,
}

pub(super) struct InnerResponse {
    pub(super) status: u16,
    pub(super) content_type: Vec<HeaderValue>,
    pub(super) body: Bytes,
}

impl From<InnerError> for InnerResponse {
    fn from(e: InnerError) -> Self {
        Self {
            status: e.status(),
            content_type: vec![HeaderValue::from_static("application/problem+json")],
            body: Bytes::from_static(e.body().as_bytes()),
        }
    }
}

const MAX_FIELD_SECTION_BYTES: u64 = 64 * 1024;

fn take_varint(rest: &mut &[u8]) -> Result<Option<u64>, InnerError> {
    let Some(&first) = rest.first() else {
        return Ok(None);
    };
    let (bytes, tail) = rest
        .split_at_checked(1 << (first >> 6))
        .ok_or(InnerError::BadRequest)?;
    let value = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |v, &b| (v << 8) | u64::from(b));
    *rest = tail;
    Ok(Some(value))
}

fn skip(rest: &mut &[u8], len: u64) -> Result<(), InnerError> {
    let len = usize::try_from(len).map_err(|_| InnerError::BadRequest)?;
    *rest = rest.get(len..).ok_or(InnerError::BadRequest)?;
    Ok(())
}

// bhttp holds every field as two Vecs, tens of times its wire size, so the sections are bounded before decoding.
// Sections missing at the end count as empty: RFC 9292 truncation, which bhttp accepts.
fn check_field_sections(mut rest: &[u8]) -> Result<(), InnerError> {
    for _ in 0..4 {
        let len = take_varint(&mut rest)?.ok_or(InnerError::BadRequest)?;
        skip(&mut rest, len)?;
    }
    for limit in [MAX_FIELD_SECTION_BYTES, u64::MAX, MAX_FIELD_SECTION_BYTES] {
        let Some(len) = take_varint(&mut rest)? else {
            return Ok(());
        };
        if len > limit {
            return Err(InnerError::BadRequest);
        }
        skip(&mut rest, len)?;
    }
    Ok(())
}

fn inner_method(control: &bhttp::ControlData) -> Result<Method, InnerError> {
    let method = control.method().ok_or(InnerError::BadRequest)?;
    let method = Method::from_bytes(method).map_err(|_| InnerError::BadRequest)?;
    if method == Method::CONNECT {
        return Err(InnerError::BadRequest);
    }
    Ok(method)
}

fn inner_path(control: &bhttp::ControlData) -> Result<&[u8], InnerError> {
    let path = control.path().ok_or(InnerError::BadRequest)?;
    if !path.starts_with(b"/")
        || path.starts_with(b"//")
        || path.contains(&b'#')
        || path.len() > MAX_PATH_AND_QUERY
    {
        return Err(InnerError::BadRequest);
    }
    Ok(path)
}

#[derive(Default)]
struct InnerFields {
    content_type: Option<HeaderValue>,
    accept: Vec<HeaderValue>,
}

fn inner_fields(header: &bhttp::Header) -> Result<InnerFields, InnerError> {
    let mut fields = InnerFields::default();
    for field in header.iter() {
        let name = field.name();
        if name.first() == Some(&b':') {
            return Err(InnerError::BadRequest);
        }
        if name.eq_ignore_ascii_case(b"content-type") {
            if fields.content_type.is_some() {
                return Err(InnerError::BadRequest);
            }
            fields.content_type = Some(field_value(field)?);
        } else if name.eq_ignore_ascii_case(b"accept") {
            fields.accept.push(field_value(field)?);
        }
    }
    Ok(fields)
}

fn field_value(field: &bhttp::Field) -> Result<HeaderValue, InnerError> {
    HeaderValue::from_bytes(field.value()).map_err(|_| InnerError::BadRequest)
}

pub(super) fn decode_inner(plaintext: &[u8]) -> Result<InnerRequest, InnerError> {
    // Known-length request framing is the single byte 0x00; bhttp does not expose the indicator.
    let Some((&0x00, framed)) = plaintext.split_first() else {
        return Err(InnerError::BadRequest);
    };
    check_field_sections(framed)?;
    let msg = bhttp::Message::read_bhttp(&mut Cursor::new(plaintext))
        .map_err(|_| InnerError::BadRequest)?;
    let method = inner_method(msg.control())?;
    let path = inner_path(msg.control())?;
    let fields = inner_fields(msg.header())?;
    if !msg.content().is_empty() && fields.content_type.is_none() {
        return Err(InnerError::UnsupportedMediaType);
    }
    Ok(InnerRequest {
        method,
        path_and_query: path.to_vec(),
        content_type: fields.content_type,
        accept: fields.accept,
        body: msg.content().to_vec(),
    })
}

struct CountElements;

impl<'de> serde::de::Visitor<'de> for CountElements {
    type Value = usize;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON array")
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<usize, A::Error> {
        let mut n = 0usize;
        while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            n += 1;
        }
        Ok(n)
    }
}

// Counts like the node: only its four whitespace bytes, only the first JSON value; no end-of-input check,
// since the node ignores trailing bytes and rejecting them would undercount what it runs.
pub(super) fn batch_size(body: &[u8]) -> usize {
    let first = body
        .iter()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
    if first != Some(&b'[') {
        return 1;
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    match serde::Deserializer::deserialize_seq(&mut de, CountElements) {
        Ok(0) | Err(_) => 1,
        Ok(n) => n,
    }
}

struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode_with_nonce(
    msg: bhttp::Message,
    nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Option<Vec<u8>> {
    let mut count = ByteCount(0);
    msg.write_bhttp(bhttp::Mode::KnownLength, &mut count).ok()?;
    let capacity = RESPONSE_NONCE_LEN
        .checked_add(count.0)?
        .checked_add(TAG_LEN)?;
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(nonce);
    if msg.write_bhttp(bhttp::Mode::KnownLength, &mut buf).is_err() {
        buf.zeroize();
        return None;
    }
    Some(buf)
}

pub(super) fn encode_response(r: &InnerResponse) -> Option<Vec<u8>> {
    let status = bhttp::StatusCode::try_from(r.status).ok()?;
    let mut msg = bhttp::Message::response(status);
    for content_type in &r.content_type {
        msg.put_header("content-type", content_type.as_bytes());
    }
    msg.write_content(&r.body);
    let mut out = Vec::new();
    msg.write_bhttp(bhttp::Mode::KnownLength, &mut out).ok()?;
    Some(out)
}
