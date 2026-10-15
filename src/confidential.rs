// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! `POST /confidential` for Ankr Confidential RPC: an encapsulated BHTTP request in, a sealed and signed BHTTP response out.

use std::io::Cursor;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Body as _;

use crate::envelope::RESPONSE_NONCE_LEN;
use crate::proxy::{collect_request, sign_or_500, UpstreamClient, MAX_PATH_AND_QUERY};
use crate::server::AppState;
use crate::signing::{SignedResponse, SigningState};

const OHTTP_KEY_PROBLEM: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key","title":"Oblivious HTTP key configuration not acceptable"}"#;

#[derive(Clone, Copy, Debug)]
pub struct ConfidentialConfig {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_batch_size: usize,
    pub upstream_timeout: std::time::Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InnerError {
    BadRequest,
    UnsupportedMediaType,
    BatchTooLarge,
    Upstream,
    UpstreamTimeout,
    Internal,
}

impl InnerError {
    fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::UnsupportedMediaType => 415,
            Self::BatchTooLarge => 413,
            Self::Upstream => 502,
            Self::UpstreamTimeout => 504,
            Self::Internal => 500,
        }
    }

    fn body(self) -> &'static str {
        match self {
            Self::BadRequest => r#"{"type":"urn:vrpc:error:bad-request","title":"Bad request"}"#,
            Self::UnsupportedMediaType => {
                r#"{"type":"urn:vrpc:error:unsupported-media-type","title":"Unsupported media type"}"#
            }
            Self::BatchTooLarge => {
                r#"{"type":"urn:vrpc:error:batch-too-large","title":"Batch too large"}"#
            }
            Self::Upstream => r#"{"type":"urn:vrpc:error:upstream","title":"Upstream error"}"#,
            Self::UpstreamTimeout => {
                r#"{"type":"urn:vrpc:error:upstream-timeout","title":"Upstream timeout"}"#
            }
            Self::Internal => r#"{"type":"urn:vrpc:error:internal","title":"Internal error"}"#,
        }
    }
}

struct InnerRequest {
    method: Method,
    path_and_query: Vec<u8>,
    content_type: Option<HeaderValue>,
    accept: Vec<HeaderValue>,
    body: Vec<u8>,
}

struct InnerResponse {
    status: u16,
    content_type: Vec<HeaderValue>,
    body: Bytes,
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

fn decode_inner(plaintext: &[u8]) -> Result<InnerRequest, InnerError> {
    // Known-length request framing is the single byte 0x00; bhttp does not expose the indicator.
    let Some((&0x00, framed)) = plaintext.split_first() else {
        return Err(InnerError::BadRequest);
    };
    check_field_sections(framed)?;
    let msg = bhttp::Message::read_bhttp(&mut Cursor::new(plaintext))
        .map_err(|_| InnerError::BadRequest)?;
    let control = msg.control();
    let method = control.method().ok_or(InnerError::BadRequest)?;
    let method = Method::from_bytes(method).map_err(|_| InnerError::BadRequest)?;
    if method == Method::CONNECT {
        return Err(InnerError::BadRequest);
    }
    let path = control.path().ok_or(InnerError::BadRequest)?;
    if !path.starts_with(b"/")
        || path.starts_with(b"//")
        || path.contains(&b'#')
        || path.len() > MAX_PATH_AND_QUERY
    {
        return Err(InnerError::BadRequest);
    }
    let mut content_type = None;
    let mut accept = Vec::new();
    for field in msg.header().iter() {
        let name = field.name();
        if name.first() == Some(&b':') {
            return Err(InnerError::BadRequest);
        }
        if name.eq_ignore_ascii_case(b"content-type") {
            if content_type.is_some() {
                return Err(InnerError::BadRequest);
            }
            content_type =
                Some(HeaderValue::from_bytes(field.value()).map_err(|_| InnerError::BadRequest)?);
        } else if name.eq_ignore_ascii_case(b"accept") {
            accept
                .push(HeaderValue::from_bytes(field.value()).map_err(|_| InnerError::BadRequest)?);
        }
    }
    if !msg.content().is_empty() && content_type.is_none() {
        return Err(InnerError::UnsupportedMediaType);
    }
    Ok(InnerRequest {
        method,
        path_and_query: path.to_vec(),
        content_type,
        accept,
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
fn batch_size(body: &[u8]) -> usize {
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

async fn call_upstream(
    upstream: &UpstreamClient,
    cfg: &ConfidentialConfig,
    inner: InnerRequest,
) -> Result<(u16, bhttp::Message), InnerError> {
    let path_and_query = upstream
        .origin_path_and_query(&inner.path_and_query)
        .ok_or(InnerError::BadRequest)?;
    let uri = upstream
        .origin_uri(path_and_query)
        .map_err(|_| InnerError::Internal)?;
    let mut builder = hyper::Request::builder().method(inner.method).uri(uri);
    if let Some(content_type) = inner.content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    for accept in inner.accept {
        builder = builder.header(ACCEPT, accept);
    }
    builder = builder.header(ACCEPT_ENCODING, "identity");
    let up_req = builder
        .body(Full::new(Bytes::from(inner.body)))
        .map_err(|_| InnerError::Internal)?;
    let call = read_upstream(upstream, cfg.max_response_bytes, up_req);
    tokio::time::timeout(cfg.upstream_timeout, call)
        .await
        .unwrap_or(Err(InnerError::UpstreamTimeout))
}

async fn read_upstream(
    upstream: &UpstreamClient,
    cap: usize,
    up_req: hyper::Request<Full<Bytes>>,
) -> Result<(u16, bhttp::Message), InnerError> {
    let resp = upstream
        .send(up_req)
        .await
        .map_err(|_| InnerError::Upstream)?;
    let (parts, mut body) = resp.into_parts();
    let status = parts.status.as_u16();
    if !(200..=599).contains(&status)
        || parts
            .headers
            .get_all(CONTENT_ENCODING)
            .iter()
            .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        || body.size_hint().lower() > u64::try_from(cap).unwrap_or(u64::MAX)
    {
        return Err(InnerError::Upstream);
    }
    let code = bhttp::StatusCode::try_from(status).map_err(|_| InnerError::Internal)?;
    let mut msg = bhttp::Message::response(code);
    for content_type in parts.headers.get_all(CONTENT_TYPE) {
        msg.put_header("content-type", content_type.as_bytes());
    }
    let mut total = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| InnerError::Upstream)?;
        if let Ok(data) = frame.into_data() {
            total = total.saturating_add(data.len());
            if total > cap {
                return Err(InnerError::Upstream);
            }
            msg.write_content(&data);
        }
    }
    Ok((status, msg))
}

fn encode_response(r: &InnerResponse) -> Option<Vec<u8>> {
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

fn pre_decapsulation_error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(CONTENT_TYPE, "application/problem+json")],
        OHTTP_KEY_PROBLEM,
    )
        .into_response()
}

fn plaintext_500() -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn build_confidential_response(
    inner_status: u16,
    batch_size: usize,
    outer_resp: Vec<u8>,
    signed: SignedResponse,
) -> Response {
    let outer_status = match inner_status {
        204 | 205 | 304 => 200,
        status => status,
    };
    Response::builder()
        .status(outer_status)
        .header(CONTENT_TYPE, "message/ohttp-res")
        .header("vRPC-Signature", signed.signature_hex())
        .header("vRPC-Timestamp", signed.timestamp_ms.to_string())
        .header("vRPC-Pubkey", signed.pubkey_hex())
        .header("vRPC-Batch-Size", batch_size.to_string())
        .body(Body::from(outer_resp))
        .unwrap_or_else(|_| plaintext_500())
}

/// Serve one Ankr Confidential RPC exchange without touching router state.
pub async fn confidential_exchange(
    upstream: &UpstreamClient,
    signer: &SigningState,
    cfg: &ConfidentialConfig,
    req: Request,
) -> Response {
    let outer_req = match collect_request(req, cfg.max_request_bytes).await {
        Ok((_, body)) => body,
        Err(resp) => return resp,
    };
    let (plaintext, ctx) = match signer.open_request(&outer_req) {
        Ok(v) => v,
        Err(_) => return pre_decapsulation_error(),
    };
    let mut nonce = [0u8; RESPONSE_NONCE_LEN];
    if getrandom::fill(&mut nonce).is_err() || crate::signing::now_ms().is_err() {
        return plaintext_500();
    }
    let (result, batch_size) = match decode_inner(&plaintext) {
        Ok(inner) => {
            let n = batch_size(&inner.body);
            if n > cfg.max_batch_size {
                (Err(InnerError::BatchTooLarge), n)
            } else {
                (call_upstream(upstream, cfg, inner).await, n)
            }
        }
        Err(e) => (Err(e), 1),
    };
    let encoded = result.and_then(|(status, msg)| {
        let mut out = Vec::new();
        msg.write_bhttp(bhttp::Mode::KnownLength, &mut out)
            .map_err(|_| InnerError::Internal)?;
        Ok((status, out))
    });
    let (status, encoded) = match encoded {
        Ok(v) => v,
        Err(e) => {
            let error = InnerResponse::from(e);
            match encode_response(&error) {
                Some(encoded) => (error.status, encoded),
                None => return plaintext_500(),
            }
        }
    };
    let outer_resp = match ctx.seal(&nonce, &encoded) {
        Ok(v) => v,
        Err(_) => return plaintext_500(),
    };
    let signed = match sign_or_500(signer, &outer_req, &outer_resp) {
        Ok(signed) => signed,
        Err(resp) => return resp,
    };
    build_confidential_response(status, batch_size, outer_resp, signed)
}

pub async fn confidential_handler(State(state): State<AppState>, req: Request) -> Response {
    confidential_exchange(&state.upstream, &state.signing, &state.confidential, req).await
}

#[cfg(test)]
mod tests;
