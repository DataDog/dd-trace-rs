// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Bridge between [`libdd_trace_inferrer`] and the OpenTelemetry SDK.
//!
//! Responsibilities:
//! - Parse the raw Lambda event payload with `libdd_trace_inferrer` to identify the trigger type
//!   and extract span metadata and carrier headers.
//! - Convert the inferred [`SpanData`](libdd_trace_inferrer::SpanData) into live OTel spans using
//!   the Datadog tracer.
//! - Expose [`TriggerContext`] so [`crate::invocation`] can parent the root span correctly.

use crate::attribute_keys as attr;
use libdd_trace_inferrer::{InferConfig, InferenceResult, SpanInferrer};

pub(crate) fn build_inferrer() -> SpanInferrer {
    #[allow(clippy::disallowed_methods)]
    let region = std::env::var("AWS_REGION").unwrap_or_default();
    SpanInferrer::new(InferConfig {
        region,
        ..InferConfig::default()
    })
}

use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use std::time::{Duration, SystemTime};

/// Metadata extracted from the trigger event, used to parent the root span.
pub(crate) struct TriggerContext {
    /// OTel context whose active span is the innermost inferred span (or the extracted
    /// propagation context when there are no inferred spans).
    pub parent_cx: Context,
    /// Whether this trigger uses asynchronous invocation semantics.
    ///
    /// When `true`, inferred span duration = `invocation_start - event_time`.
    /// When `false`, inferred span duration = `invocation_end - event_time`.
    pub is_async: bool,
    /// Short name of the outermost trigger, e.g. `"sqs"`. Added as a tag on the root span.
    pub event_source: Option<String>,
    /// ARN of the outermost trigger resource. Added as a tag on the root span when present.
    pub event_source_arn: Option<String>,
}

/// An inferred span that is currently open, held as an OTel context.
struct ActiveInferredSpan {
    /// OTel context whose active span is this inferred span.
    cx: Context,
    /// Mirrors [`TriggerContext::is_async`] — determines the end-time passed to
    /// [`InferredSpanScope::end`].
    is_async: bool,
    /// Source event timestamp for this inferred span, when known.
    start_time: Option<SystemTime>,
}

/// Handle for the set of inferred spans created for a trigger.
pub(crate) struct InferredSpanScope {
    outer: Option<ActiveInferredSpan>,
    inner: Option<ActiveInferredSpan>,
}

impl InferredSpanScope {
    pub(crate) fn empty() -> Self {
        Self {
            outer: None,
            inner: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_none()
    }

    /// Creates inferred spans from an [`InferenceResult`].
    ///
    /// Call [`innermost_context`](Self::innermost_context) after construction to get the
    /// OTel context whose active span is the innermost inferred span (e.g., SQS inside
    /// SNS). Callers should use that context as the parent for the `aws.lambda` root span.
    pub(crate) fn start(tracer: &SdkTracer, parent_cx: &Context, result: &InferenceResult) -> Self {
        if !result.should_create_inferred_span() {
            return Self::empty();
        }

        let mut current_cx = parent_cx.clone();

        let outer = result
            .wrapped_span
            .as_ref()
            .filter(|w| w.should_create_inferred_span())
            .map(|w| {
                current_cx = build_inferred_span(tracer, &w.span_data, &current_cx);
                ActiveInferredSpan {
                    cx: current_cx.clone(),
                    is_async: w.is_async,
                    start_time: inferred_span_start_time(&w.span_data),
                }
            });

        current_cx = build_inferred_span(tracer, &result.span_data, &current_cx);
        let inner = Some(ActiveInferredSpan {
            cx: current_cx,
            is_async: result.is_async,
            start_time: inferred_span_start_time(&result.span_data),
        });

        Self { outer, inner }
    }

    /// Returns the OTel context of the innermost inferred span.
    ///
    /// Falls back to `fallback` (typically the upstream propagation context) when no
    /// inferred spans were created. Callers should use this as the parent for the root span.
    pub(crate) fn innermost_context(&self, fallback: &Context) -> Context {
        self.inner
            .as_ref()
            .map(|s| s.cx.clone())
            .unwrap_or_else(|| fallback.clone())
    }

    /// End all inferred spans with correct timing.
    ///
    /// Wrapped outer spans end when the inner event begins.
    /// Inner async spans end at invocation start (propagation delay).
    /// Inner sync spans end at invocation end (full request duration).
    pub(crate) fn end(&self, invocation_start: SystemTime, invocation_end: SystemTime) {
        if let Some(outer) = self.outer.as_ref() {
            let outer_end_time = self
                .inner
                .as_ref()
                .and_then(|inner| inner.start_time)
                .unwrap_or(invocation_start);
            outer.cx.span().end_with_timestamp(outer_end_time);
        }

        if let Some(inner) = self.inner.as_ref() {
            let end_time = if inner.is_async {
                invocation_start
            } else {
                invocation_end
            };
            inner.cx.span().end_with_timestamp(end_time);
        }
    }
}

fn inferred_span_start_time(span_data: &libdd_trace_inferrer::SpanData) -> Option<SystemTime> {
    let start_ns = u64::try_from(span_data.start).ok()?;
    (start_ns > 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_nanos(start_ns))
}

/// Converts a [`libdd_trace_inferrer::SpanData`] into a live OTel span.
///
/// Returns a new OTel context with the new span as the active span. All metadata
/// from `span_data.meta` is added as span attributes.
///
/// If `span_data.start` is zero or negative (unknown event time), the OTel SDK
/// assigns the current wall-clock time as the start time.
fn build_inferred_span(
    tracer: &SdkTracer,
    span_data: &libdd_trace_inferrer::SpanData,
    parent_cx: &Context,
) -> Context {
    let mut builder = tracer.span_builder(span_data.name.clone());
    builder.span_kind = Some(SpanKind::Server);

    if let Some(start_time) = inferred_span_start_time(span_data) {
        builder.start_time = Some(start_time);
    }

    let mut attrs = vec![
        KeyValue::new(attr::SERVICE_NAME, span_data.service.clone()),
        KeyValue::new(attr::RESOURCE_NAME, span_data.resource.clone()),
        KeyValue::new(attr::SPAN_TYPE, span_data.r#type.clone()),
        KeyValue::new(attr::OPERATION_NAME, span_data.name.clone()),
        KeyValue::new(attr::OPERATION_NAME_CUSTOM, span_data.name.clone()),
        KeyValue::new(attr::SERVICE_PEER_NAME, span_data.service.clone()),
    ];
    for (k, v) in &span_data.meta {
        attrs.push(KeyValue::new(k.clone(), v.clone()));
    }
    builder.attributes = Some(attrs);

    let span = tracer.build_with_context(builder, parent_cx);
    parent_cx.with_span(span)
}

/// Output of [`extract_trigger`].
pub(crate) struct TriggerExtraction {
    /// OTel context extracted from the trigger's carrier headers.
    ///
    /// Contains the upstream trace/span IDs when the trigger carries Datadog propagation
    /// headers. Falls back to the ambient context when no valid carrier is found.
    pub upstream_cx: Context,
    /// Full inference result from `libdd_trace_inferrer`, including span data, trigger
    /// tags, and async/sync classification.
    pub inference_result: InferenceResult,
    /// Whether this trigger uses asynchronous invocation semantics.
    pub is_async: bool,
    /// Short name of the outermost trigger, e.g. `"sqs"`. Added as a tag on the root span.
    pub event_source: Option<String>,
    /// ARN of the outermost trigger resource. Added as a tag on the root span when present.
    pub event_source_arn: Option<String>,
}

/// Infers trigger metadata from `payload` and extracts the upstream OTel context.
///
/// Carrier extraction uses `x-datadog-trace-id` as a sentinel: a missing or zero
/// trace ID means there are no upstream headers to propagate, so we fall back to
/// the ambient context rather than accidentally creating a span parented to trace ID 0.
pub(crate) fn extract_trigger(inferrer: &SpanInferrer, payload: &str) -> TriggerExtraction {
    let result = inferrer.infer_span(payload).unwrap_or_default();
    let trace_id = result.carrier.get("x-datadog-trace-id").map(String::as_str);
    let has_upstream_trace = trace_id
        .and_then(|id| id.parse::<u64>().ok())
        .is_some_and(|id| id != 0);

    let upstream_cx = global::get_text_map_propagator(|p| {
        if has_upstream_trace {
            tracing::debug!(
                trace_id = trace_id.unwrap_or("?"),
                "extracted trace context from trigger"
            );
            p.extract(&result.carrier)
        } else {
            tracing::debug!("no trace context found in event");
            Context::current()
        }
    });

    TriggerExtraction {
        upstream_cx,
        is_async: result.is_async,
        event_source: result
            .trigger_tags
            .get("function_trigger.event_source")
            .cloned(),
        event_source_arn: result
            .trigger_tags
            .get("function_trigger.event_source_arn")
            .cloned(),
        inference_result: result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libdd_trace_inferrer::{InferenceResult, SpanData};
    use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
    use opentelemetry::Value as OtelValue;
    use opentelemetry_sdk::trace::{
        InMemorySpanExporter, SdkTracerProvider, SpanData as OtelSpanData,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::time::SystemTime;

    fn test_provider() -> (SdkTracerProvider, InMemorySpanExporter) {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        (provider, exporter)
    }

    fn find_attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a OtelValue> {
        attrs
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| &kv.value)
    }

    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<OtelSpanData> {
        exporter.get_finished_spans().unwrap()
    }

    fn make_result(name: &str, service: &str) -> InferenceResult {
        InferenceResult {
            span_data: SpanData {
                name: name.to_string(),
                service: service.to_string(),
                resource: service.to_string(),
                r#type: "web".to_string(),
                start: 0,
                meta: HashMap::new(),
            },
            is_async: false,
            ..InferenceResult::default()
        }
    }

    fn nanos_to_system_time(ns: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(ns)
    }

    #[test]
    fn sets_expected_attributes_on_inferred_spans() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let result = make_result("aws.sqs", "my-queue");
        let scope = InferredSpanScope::start(&tracer, &Context::current(), &result);
        let now = SystemTime::now();
        scope.end(now, now);
        provider.force_flush().ok();

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 1);
        let attrs = &spans[0].attributes;

        assert_eq!(
            find_attr(attrs, "service.name"),
            Some(&OtelValue::String("my-queue".into()))
        );
        assert_eq!(
            find_attr(attrs, "resource.name"),
            Some(&OtelValue::String("my-queue".into()))
        );
        assert_eq!(
            find_attr(attrs, "operation.name"),
            Some(&OtelValue::String("aws.sqs".into()))
        );
        assert_eq!(
            find_attr(attrs, "operation_name"),
            Some(&OtelValue::String("aws.sqs".into()))
        );
    }

    #[test]
    fn chains_inferred_spans() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let mut result = make_result("aws.sqs", "my-queue");
        result.wrapped_span = Some(Box::new(make_result("aws.sns", "my-topic")));

        let parent_cx = Context::current();
        let scope = InferredSpanScope::start(&tracer, &parent_cx, &result);
        let cx = scope.innermost_context(&parent_cx);
        let now = SystemTime::now();
        scope.end(now, now);
        provider.force_flush().ok();

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 2);
        // Innermost span (sqs) should be the active span in the returned context
        assert_eq!(
            cx.span().span_context().span_id(),
            spans
                .iter()
                .find(|s| s.name == "aws.sqs")
                .unwrap()
                .span_context
                .span_id()
        );
    }

    #[test]
    fn wrapped_span_ends_when_inner_span_starts() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let outer_start_ns = 1_000_000_000;
        let inner_start_ns = 2_000_000_000;
        let invocation_start = nanos_to_system_time(10_000_000_000);
        let invocation_end = nanos_to_system_time(20_000_000_000);

        let mut result = make_result("aws.sqs", "my-queue");
        result.span_data.start = inner_start_ns as i64;
        result.is_async = true;

        let mut wrapped = make_result("aws.sns", "my-topic");
        wrapped.span_data.start = outer_start_ns as i64;
        result.wrapped_span = Some(Box::new(wrapped));

        let scope = InferredSpanScope::start(&tracer, &Context::current(), &result);
        scope.end(invocation_start, invocation_end);
        provider.force_flush().ok();

        let spans = finished_spans(&exporter);
        let outer = spans.iter().find(|s| s.name == "aws.sns").unwrap();
        let inner = spans.iter().find(|s| s.name == "aws.sqs").unwrap();

        assert_eq!(outer.end_time, inner.start_time);
    }

    #[test]
    fn preserves_parent_context_when_no_inferred_spans_are_created() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");
        let parent_cx = Context::current();
        let empty_result = InferenceResult::default();
        let scope = InferredSpanScope::start(&tracer, &parent_cx, &empty_result);
        let result_cx = scope.innermost_context(&parent_cx);

        assert_eq!(
            result_cx.span().span_context().trace_id(),
            parent_cx.span().span_context().trace_id()
        );
        assert!(scope.is_empty());
    }

    #[test]
    fn extracts_trigger_context_from_sqs_event() {
        let carrier_json = json!({
            "x-datadog-trace-id": "12345",
            "x-datadog-parent-id": "67890",
            "x-datadog-sampling-priority": "1"
        });
        let event = json!({
            "Records": [{
                "messageId": "msg-001",
                "receiptHandle": "receipt-001",
                "eventSource": "aws:sqs",
                "eventSourceARN": "arn:aws:sqs:us-east-1:123456789:test-queue",
                "awsRegion": "us-east-1",
                "body": "hello",
                "md5OfBody": "d8e8fca2dc0f896fd7cb4cb0031ba249",
                "attributes": {
                    "SentTimestamp": "1718444400000",
                    "ApproximateFirstReceiveTimestamp": "1718444400100",
                    "ApproximateReceiveCount": "1",
                    "SenderId": "AIDAIENQZJOLO23YVJ4VO"
                },
                "messageAttributes": {
                    "_datadog": {
                        "stringValue": serde_json::to_string(&carrier_json).unwrap(),
                        "dataType": "String"
                    }
                }
            }]
        });

        let inferrer = build_inferrer();
        let extraction = extract_trigger(&inferrer, &event.to_string());

        assert!(extraction.inference_result.is_async);
        assert_eq!(
            extraction
                .inference_result
                .trigger_tags
                .get("function_trigger.event_source")
                .map(String::as_str),
            Some("sqs")
        );
        assert!(extraction.inference_result.should_create_inferred_span());
        assert_eq!(extraction.inference_result.span_data.name, "aws.sqs");
    }
}
