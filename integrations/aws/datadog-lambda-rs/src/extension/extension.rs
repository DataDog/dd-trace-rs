// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use super::constants::{EXTENSION_PORT, LAMBDA_REQUEST_ID_HEADER};
use crate::logger::{dd_lambda_error, dd_lambda_warn};
use crate::trace_headers::{
    DATADOG_PARENT_ID_KEY, DATADOG_SAMPLING_PRIORITY_KEY, DATADOG_SPAN_ID_KEY, DATADOG_TAGS_KEY,
    DATADOG_TRACE_ID_KEY,
};
use opentelemetry::trace::{SpanContext, TraceContextExt, TraceFlags, TraceState};
use opentelemetry::Context;
use opentelemetry_sdk::trace::{IdGenerator, RandomIdGenerator};
use serde::Serialize;
use serde_json::json;
use std::sync::OnceLock;
use std::time::Duration;

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to create HTTP client")
    })
}

/// Notify the extension that an invocation has started.
///
/// Returns `(Context, parent_id)` where `parent_id` is from
/// `x-datadog-parent-id` or defaults to `trace_id`.
pub(crate) async fn start_invocation<E: Serialize>(
    request_id: &str,
    event: &E,
) -> Option<(Context, u64)> {
    let client = get_http_client();
    let url = format!("http://127.0.0.1:{EXTENSION_PORT}/lambda/start-invocation");

    let response = client
        .post(&url)
        .header(LAMBDA_REQUEST_ID_HEADER, request_id)
        .json(event)
        .send()
        .await
        .map_err(|e| {
            dd_lambda_warn!("start-invocation failed: {e}");
        })
        .ok()?;

    let headers = response.headers().clone();
    // Consume the body to release the connection.
    let _ = response.text().await;

    parse_extension_response(&headers)
}

/// Parse trace context from extension response headers.
///
/// Extracts `trace_id`, `parent_id`, sampling priority, and
/// `_dd.p.tid` (upper 64 bits of 128-bit trace ID) from the response
/// headers. Builds an OTel [`SpanContext`] and returns
/// `(Context, parent_id)`.
fn parse_extension_response(headers: &reqwest::header::HeaderMap) -> Option<(Context, u64)> {
    let trace_id_str = headers
        .get(DATADOG_TRACE_ID_KEY)
        .and_then(|v| v.to_str().ok())?;

    let trace_id_low: u64 = trace_id_str.parse().ok().filter(|&v| v != 0)?;

    // If the extension returns x-datadog-parent-id, use it; otherwise
    // default to trace_id (matches datadog-lambda-go).
    let parent_id = headers
        .get(DATADOG_PARENT_ID_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(trace_id_low);

    let tid_high = headers
        .get(DATADOG_TAGS_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|tags| {
            tags.split(',')
                .find(|t| t.starts_with("_dd.p.tid="))
                .and_then(|t| u64::from_str_radix(t.trim_start_matches("_dd.p.tid="), 16).ok())
        })
        .unwrap_or(0);

    let mut trace_id_bytes = [0u8; 16];
    trace_id_bytes[..8].copy_from_slice(&tid_high.to_be_bytes());
    trace_id_bytes[8..].copy_from_slice(&trace_id_low.to_be_bytes());
    let trace_id = opentelemetry::trace::TraceId::from_bytes(trace_id_bytes);

    let span_id = RandomIdGenerator::default().new_span_id();

    let sampling = headers
        .get(DATADOG_SAMPLING_PRIORITY_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(1);

    let flags = if sampling > 0 {
        TraceFlags::SAMPLED
    } else {
        TraceFlags::default()
    };

    let span_context = SpanContext::new(trace_id, span_id, flags, true, TraceState::default());

    Some((
        Context::current().with_remote_span_context(span_context),
        parent_id,
    ))
}

/// Notify the extension that an invocation has ended.
pub(crate) async fn end_invocation(
    request_id: &str,
    is_error: bool,
    trace_id: u64,
    parent_id: u64,
    span_id: u64,
    sampling_priority: i32,
) {
    let client = get_http_client();
    let url = format!("http://127.0.0.1:{EXTENSION_PORT}/lambda/end-invocation");

    if let Err(e) = client
        .post(&url)
        .header(LAMBDA_REQUEST_ID_HEADER, request_id)
        .header(DATADOG_TRACE_ID_KEY, trace_id.to_string())
        .header(DATADOG_PARENT_ID_KEY, parent_id.to_string())
        .header(DATADOG_SPAN_ID_KEY, span_id.to_string())
        .header(DATADOG_SAMPLING_PRIORITY_KEY, sampling_priority.to_string())
        .json(&json!({ "isError": is_error }))
        .send()
        .await
    {
        dd_lambda_error!("end-invocation failed: {e}");
    }
}
