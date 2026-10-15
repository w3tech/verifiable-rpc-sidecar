// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Web3 Technologies, Inc.

//! The bounded upstream leg of `/confidential`: one inner request out, one capped BHTTP response back.

use axum::http::header::{ACCEPT, ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Body as _;

use super::inner::InnerRequest;
use super::{ConfidentialConfig, InnerError};
use crate::proxy::UpstreamClient;

pub(super) async fn call_upstream(
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
