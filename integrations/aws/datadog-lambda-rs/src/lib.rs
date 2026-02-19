// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog Lambda tracing for Rust.
//!
//! Provides instrumentation for AWS Lambda functions using the Datadog
//! Lambda extension for trace context propagation and span management.
//!
//! # Usage
//!
//! ```ignore
//! use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
//! use lambda_runtime::{service_fn, Error, LambdaEvent};
//! use serde_json::Value;
//!
//! async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
//!     Ok(Value::Null)
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     let provider = /* configure your SdkTracerProvider */;
//!     set_tracer_provider(provider);
//!     lambda_runtime::run(service_fn(wrap_handler(handler))).await
//! }
//! ```

// TODO(libdd-inferrer): When libdd-inferrer replaces the extension,
// this crate will need to handle root span creation, cold-start spans,
// synthetic/inferred spans, and trace context extraction locally.
// See README.md roadmap for the full breakdown.

mod extension;
#[allow(dead_code, unused_macros, unused_imports)]
mod logger;
use logger::{dd_lambda_error, dd_lambda_warn};
mod trace_headers;

use lambda_runtime::LambdaEvent;
use opentelemetry::trace::{FutureExt, SpanContext, TraceContextExt, TraceFlags, TraceState};
use opentelemetry::Context;
use opentelemetry_sdk::trace::{IdGenerator, RandomIdGenerator, SdkTracerProvider};
use serde::Serialize;
use std::sync::{Arc, OnceLock};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

const DEFAULT_SAMPLING_PRIORITY: i32 = 1;

static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Register the [`SdkTracerProvider`] used to flush pending spans.
///
/// Call once during Lambda cold-start initialization. Subsequent calls
/// are no-ops.
pub fn set_tracer_provider(provider: SdkTracerProvider) {
    if TRACER_PROVIDER.set(provider).is_err() {
        dd_lambda_warn!("tracer provider already set, ignoring");
    }
}

/// Create the root span context for a Lambda invocation.
///
/// Calls the extension's `start_invocation` endpoint which extracts
/// trace context from the event payload and returns it. Falls back to
/// generating random trace/span IDs if the extension is unavailable.
///
/// Returns `(Context, parent_id)` where `parent_id` is from the
/// extension's `x-datadog-parent-id` header or defaults to `trace_id`
/// (matching `datadog-lambda-go` behaviour). Pass both values to
/// [`end_root_span`] after the handler completes.
#[must_use = "the returned Context must be used to parent child spans"]
pub async fn create_root_span<E: Serialize>(
    request_id: &str,
    event: &LambdaEvent<E>,
) -> (Context, u64) {
    if let Some(result) = extension::start_invocation(request_id, &event.payload).await {
        return result;
    }

    let id_gen = RandomIdGenerator::default();
    let trace_id = id_gen.new_trace_id();
    let span_id = id_gen.new_span_id();
    let span_context = SpanContext::new(
        trace_id,
        span_id,
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    );
    let trace_id_low = u64::from_be_bytes(
        trace_id.to_bytes()[8..16]
            .try_into()
            .expect("slice is exactly 8 bytes"),
    );
    (
        Context::current().with_remote_span_context(span_context),
        trace_id_low,
    )
}

/// Signal the extension that the invocation has ended.
///
/// Extracts trace and span IDs from `parent_cx` and forwards them,
/// along with `parent_id` from [`create_root_span`], to the extension.
pub async fn end_root_span(request_id: &str, is_error: bool, parent_cx: &Context, parent_id: u64) {
    let span_ctx = parent_cx.span().span_context().clone();
    let trace_id = u64::from_be_bytes(
        span_ctx.trace_id().to_bytes()[8..16]
            .try_into()
            .expect("slice is exactly 8 bytes"),
    );
    let span_id = u64::from_be_bytes(span_ctx.span_id().to_bytes());

    extension::end_invocation(
        request_id,
        is_error,
        trace_id,
        parent_id,
        span_id,
        DEFAULT_SAMPLING_PRIORITY,
    )
    .await;
}

pub fn flush_all_spans() {
    let provider = TRACER_PROVIDER
        .get()
        .expect("set_tracer_provider must be called before flush_all_spans");
    if let Err(e) = provider.force_flush() {
        dd_lambda_error!("flush failed: {e}");
    }
}

/// Wrap a Lambda handler with Datadog tracing.
///
/// On each invocation:
/// 1. Calls the extension to start the invocation and get trace context
/// 2. Runs the handler with child spans parented to that context
/// 3. Signals the extension that the invocation has ended
/// 4. Flushes pending spans via the registered tracer provider
///
/// The `E` type parameter must implement [`Serialize`] because the
/// event payload is forwarded to the extension for trace context
/// extraction.
pub fn wrap_handler<F, Fut, E, R>(
    handler: F,
) -> impl Fn(LambdaEvent<E>) -> BoxFuture<Result<R, lambda_runtime::Error>>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, lambda_runtime::Error>> + Send + 'static,
    E: Serialize + Send + Sync + 'static,
    R: Send + 'static,
{
    let handler = Arc::new(handler);
    move |event: LambdaEvent<E>| {
        let handler = handler.clone();
        Box::pin(async move {
            let request_id = event.context.request_id.clone();

            let (parent_cx, parent_id) = create_root_span(&request_id, &event).await;

            let result = handler(event).with_context(parent_cx.clone()).await;

            end_root_span(&request_id, result.is_err(), &parent_cx, parent_id).await;

            flush_all_spans();

            result
        })
    }
}
