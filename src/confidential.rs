// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! `POST /confidential` for Ankr Confidential RPC: an encapsulated BHTTP request in, a sealed and signed BHTTP response out.

mod inner;
mod upstream;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use zeroize::Zeroizing;

use self::inner::{batch_size, decode_inner, encode_response, encode_with_nonce, InnerResponse};
use self::upstream::call_upstream;
use crate::envelope::{ResponseContext, RESPONSE_NONCE_LEN};
use crate::proxy::UpstreamClient;
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

    fn class(self) -> OutcomeClass {
        match self {
            Self::BadRequest => OutcomeClass::BadRequest,
            Self::UnsupportedMediaType => OutcomeClass::UnsupportedMediaType,
            Self::BatchTooLarge => OutcomeClass::BatchTooLarge,
            Self::Upstream => OutcomeClass::Upstream,
            Self::UpstreamTimeout => OutcomeClass::UpstreamTimeout,
            Self::Internal => OutcomeClass::Internal,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutcomeClass {
    Ok,
    BadRequest,
    UnsupportedMediaType,
    BatchTooLarge,
    Upstream,
    UpstreamTimeout,
    Internal,
    PreDecapsulation,
    RequestTooLarge,
    RequestReadFailed,
    MethodNotAllowed,
    Unsealable,
    Cancelled,
}

impl OutcomeClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadRequest => "bad-request",
            Self::UnsupportedMediaType => "unsupported-media-type",
            Self::BatchTooLarge => "batch-too-large",
            Self::Upstream => "upstream",
            Self::UpstreamTimeout => "upstream-timeout",
            Self::Internal => "internal",
            Self::PreDecapsulation => "pre-decapsulation",
            Self::RequestTooLarge => "request-too-large",
            Self::RequestReadFailed => "request-read-failed",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::Unsealable => "unsealable",
            Self::Cancelled => "cancelled",
        }
    }
}

struct Outcome {
    class: OutcomeClass,
    inner_status: u16,
    batch_size: usize,
    request_bytes: usize,
    response_bytes: usize,
    upstream_ms: u64,
}

impl Outcome {
    fn plaintext(class: OutcomeClass, request_bytes: usize, response_bytes: usize) -> Self {
        Self {
            class,
            inner_status: 0,
            batch_size: 0,
            request_bytes,
            response_bytes,
            upstream_ms: 0,
        }
    }
}

fn log_outcome(o: &Outcome, status: u16, total_ms: u64) {
    tracing::info!(
        outcome = o.class.as_str(),
        status,
        inner_status = o.inner_status,
        batch_size = o.batch_size,
        request_bytes = o.request_bytes,
        response_bytes = o.response_bytes,
        upstream_ms = o.upstream_ms,
        total_ms,
        "confidential call"
    );
}

fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
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
    let mut guard = OutcomeGuard {
        started: std::time::Instant::now(),
        done: None,
    };
    let (resp, outcome) = exchange(upstream, signer, cfg, req).await;
    guard.done = Some((outcome, resp.status().as_u16()));
    resp
}

/// Logs the outcome on drop, so a call dropped mid-flight (client gone) still gets its line.
struct OutcomeGuard {
    started: std::time::Instant,
    done: Option<(Outcome, u16)>,
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        let (outcome, status) = self
            .done
            .take()
            .unwrap_or_else(|| (Outcome::plaintext(OutcomeClass::Cancelled, 0, 0), 0));
        log_outcome(&outcome, status, millis(self.started.elapsed()));
    }
}

struct InnerCall {
    result: Result<(u16, bhttp::Message), InnerError>,
    batch_size: usize,
    upstream_ms: u64,
}

impl InnerCall {
    fn failed(e: InnerError, batch_size: usize) -> Self {
        Self {
            result: Err(e),
            batch_size,
            upstream_ms: 0,
        }
    }
}

async fn run_inner(
    upstream: &UpstreamClient,
    cfg: &ConfidentialConfig,
    plaintext: Zeroizing<Vec<u8>>,
) -> InnerCall {
    let decoded = decode_inner(&plaintext);
    drop(plaintext);
    let inner = match decoded {
        Ok(inner) => inner,
        Err(e) => return InnerCall::failed(e, 1),
    };
    let n = batch_size(&inner.body);
    if n > cfg.max_batch_size {
        return InnerCall::failed(InnerError::BatchTooLarge, n);
    }
    let called = std::time::Instant::now();
    let result = call_upstream(upstream, cfg, inner).await;
    InnerCall {
        result,
        batch_size: n,
        upstream_ms: millis(called.elapsed()),
    }
}

struct Sealed {
    class: OutcomeClass,
    inner_status: u16,
    body: Vec<u8>,
}

fn seal_inner(
    ctx: ResponseContext,
    nonce: &[u8; RESPONSE_NONCE_LEN],
    result: Result<(u16, bhttp::Message), InnerError>,
) -> Option<Sealed> {
    let encoded = result.and_then(|(status, msg)| {
        encode_with_nonce(msg, nonce)
            .map(|buf| (status, buf))
            .ok_or(InnerError::Internal)
    });
    match encoded {
        Ok((inner_status, mut body)) => {
            ctx.seal_in_place(&mut body).ok()?;
            Some(Sealed {
                class: OutcomeClass::Ok,
                inner_status,
                body,
            })
        }
        Err(e) => {
            let error = InnerResponse::from(e);
            let encoded = encode_response(&error)?;
            Some(Sealed {
                class: e.class(),
                inner_status: error.status,
                body: ctx.seal(nonce, &encoded).ok()?,
            })
        }
    }
}

fn unsealable(request_bytes: usize, batch_size: usize, upstream_ms: u64) -> Outcome {
    Outcome {
        batch_size,
        upstream_ms,
        ..Outcome::plaintext(OutcomeClass::Unsealable, request_bytes, 0)
    }
}

/// The plaintext answer of a call that ends before a sealed response exists.
fn plaintext_response(class: OutcomeClass) -> Response {
    match class {
        OutcomeClass::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        OutcomeClass::RequestReadFailed => StatusCode::BAD_REQUEST.into_response(),
        OutcomeClass::PreDecapsulation => pre_decapsulation_error(),
        _ => plaintext_500(),
    }
}

async fn read_outer(req: Request, cap: usize) -> Result<Bytes, Outcome> {
    match Limited::new(req.into_body(), cap).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => {
            let class = if e.is::<LengthLimitError>() {
                OutcomeClass::RequestTooLarge
            } else {
                OutcomeClass::RequestReadFailed
            };
            Err(Outcome::plaintext(class, 0, 0))
        }
    }
}

async fn exchange(
    upstream: &UpstreamClient,
    signer: &SigningState,
    cfg: &ConfidentialConfig,
    req: Request,
) -> (Response, Outcome) {
    match sealed_exchange(upstream, signer, cfg, req).await {
        Ok(done) => done,
        Err(outcome) => (plaintext_response(outcome.class), outcome),
    }
}

async fn sealed_exchange(
    upstream: &UpstreamClient,
    signer: &SigningState,
    cfg: &ConfidentialConfig,
    req: Request,
) -> Result<(Response, Outcome), Outcome> {
    let outer_req = read_outer(req, cfg.max_request_bytes).await?;
    let request_bytes = outer_req.len();
    let (plaintext, ctx) = signer.open_request(&outer_req).map_err(|_| {
        Outcome::plaintext(
            OutcomeClass::PreDecapsulation,
            request_bytes,
            OHTTP_KEY_PROBLEM.len(),
        )
    })?;
    let plaintext = Zeroizing::new(plaintext);
    let mut nonce = [0u8; RESPONSE_NONCE_LEN];
    if getrandom::fill(&mut nonce).is_err() || crate::signing::now_ms().is_err() {
        return Err(unsealable(request_bytes, 0, 0));
    }
    let call = run_inner(upstream, cfg, plaintext).await;
    let failed = || unsealable(request_bytes, call.batch_size, call.upstream_ms);
    let sealed = seal_inner(ctx, &nonce, call.result).ok_or_else(failed)?;
    let signed = signer
        .sign(&outer_req, &sealed.body)
        .map_err(|_| failed())?;
    let outcome = Outcome {
        class: sealed.class,
        inner_status: sealed.inner_status,
        batch_size: call.batch_size,
        request_bytes,
        response_bytes: sealed.body.len(),
        upstream_ms: call.upstream_ms,
    };
    let resp =
        build_confidential_response(sealed.inner_status, call.batch_size, sealed.body, signed);
    Ok((resp, outcome))
}

pub async fn confidential_method_not_allowed() -> Response {
    log_outcome(
        &Outcome::plaintext(OutcomeClass::MethodNotAllowed, 0, 0),
        StatusCode::METHOD_NOT_ALLOWED.as_u16(),
        0,
    );
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

pub async fn confidential_handler(State(state): State<AppState>, req: Request) -> Response {
    confidential_exchange(&state.upstream, &state.signing, &state.confidential, req).await
}

#[cfg(test)]
mod tests;
