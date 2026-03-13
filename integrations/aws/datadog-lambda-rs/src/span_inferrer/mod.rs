// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod carrier;
mod triggers;

use carrier::{
    carrier_from_json_object, validate_carrier, CARRIER_KEY, PARENT_ID_KEY, SAMPLING_PRIORITY_KEY,
    TAGS_KEY, TRACE_ID_KEY,
};
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Descriptor for an inferred span representing an AWS service trigger.
///
/// Spans in a trigger extraction result are ordered outer to inner;
/// the last is the direct parent of the Lambda invocation span.
pub(crate) struct InferredSpan {
    /// e.g. `"aws.sqs"`, `"aws.sns"`, `"aws.eventbridge"`
    pub operation: &'static str,
    /// Short trigger source name, e.g. `"sqs"`, `"sns"`, `"eventbridge"`.
    pub trigger_source: &'static str,
    /// ARN of the trigger resource, if available.
    pub trigger_arn: Option<String>,
    pub service: String,
    pub resource: String,
    /// Currently always `"web"`.
    pub span_type: &'static str,
    /// Nanoseconds since Unix epoch.
    pub start_time_ns: Option<i64>,
    pub is_async: bool,
    /// e.g. `source_arn`, `message_id`
    pub tags: HashMap<String, String>,
}

pub(crate) struct InferredContext {
    /// OTel context whose active span is the innermost inferred span.
    /// Falls back to extracted headers context or `Context::current()`.
    pub parent_cx: Context,
    pub is_async: bool,
    /// Short name of the outermost trigger, e.g. `"sqs"`.
    pub event_source: Option<&'static str>,
    /// ARN of the outermost trigger resource.
    pub event_source_arn: Option<String>,
    /// One context per inferred span, in creation order.
    /// Spans are left open so `open_span_count > 0` while the root span is created.
    /// Call `end_with_timestamp` on each after `create_root_span`.
    pub inferred_span_contexts: Vec<Context>,
    pub inferred_span_end_time: SystemTime,
}

/// Owns the entire "event payload → OTel parent context" pipeline.
///
/// Given a raw Lambda event payload, detects the trigger type, extracts
/// Datadog trace context, creates inferred OTel spans for upstream services,
/// and returns a context ready to parent the invocation root span.
pub(crate) struct SpanInferrer<'a> {
    tracer: &'a SdkTracer,
}

impl<'a> SpanInferrer<'a> {
    pub(crate) fn new(tracer: &'a SdkTracer) -> Self {
        Self { tracer }
    }

    /// Extract trace context from the payload, create inferred OTel spans,
    /// and return a context ready to parent the invocation root span.
    pub(crate) fn infer(&self, payload: &Value) -> InferredContext {
        if let Some((carrier, inferred_spans)) = triggers::extract(payload) {
            if validate_carrier(&carrier).is_some() {
                tracing::debug!(
                    trace_id = carrier.get(TRACE_ID_KEY).map(String::as_str).unwrap_or("?"),
                    inferred_spans = inferred_spans.len(),
                    "extracted trace context from trigger"
                );
                let extracted_cx = global::get_text_map_propagator(|p| p.extract(&carrier));
                let is_async = inferred_spans.last().map(|s| s.is_async).unwrap_or(false);
                let event_source = inferred_spans.first().map(|s| s.trigger_source);
                let event_source_arn = inferred_spans.first().and_then(|s| s.trigger_arn.clone());
                let (parent_cx, inferred_span_contexts, inferred_span_end_time) =
                    if inferred_spans.is_empty() {
                        (extracted_cx, Vec::new(), SystemTime::now())
                    } else {
                        self.create_inferred_spans(&extracted_cx, &inferred_spans)
                    };
                return InferredContext {
                    parent_cx,
                    is_async,
                    event_source,
                    event_source_arn,
                    inferred_span_contexts,
                    inferred_span_end_time,
                };
            }
        }

        if let Some(carrier) = extract_from_headers(payload) {
            if validate_carrier(&carrier).is_some() {
                tracing::debug!(
                    trace_id = carrier.get(TRACE_ID_KEY).map(String::as_str).unwrap_or("?"),
                    "extracted trace context from headers"
                );
                let extracted_cx = global::get_text_map_propagator(|p| p.extract(&carrier));
                return InferredContext {
                    parent_cx: extracted_cx,
                    is_async: false,
                    event_source: None,
                    event_source_arn: None,
                    inferred_span_contexts: Vec::new(),
                    inferred_span_end_time: SystemTime::now(),
                };
            }
        }

        tracing::debug!("no trace context found in event");
        InferredContext {
            parent_cx: Context::current(),
            is_async: false,
            event_source: None,
            event_source_arn: None,
            inferred_span_contexts: Vec::new(),
            inferred_span_end_time: SystemTime::now(),
        }
    }

    // Spans are created outer to inner; the returned context's active span is the
    // innermost (direct parent of the invocation span).
    fn create_inferred_spans(
        &self,
        parent_cx: &Context,
        inferred: &[InferredSpan],
    ) -> (Context, Vec<Context>, SystemTime) {
        let mut current_cx = parent_cx.clone();
        let now = SystemTime::now();
        let mut span_contexts = Vec::with_capacity(inferred.len());

        for desc in inferred {
            let mut builder = self.tracer.span_builder(desc.operation);
            builder.span_kind = Some(SpanKind::Server);
            if let Some(start_ns) = desc.start_time_ns {
                let start_ns = u64::try_from(start_ns).unwrap_or(0);
                builder.start_time = Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(start_ns));
            }
            let mut attrs = vec![
                KeyValue::new("service.name", desc.service.clone()),
                KeyValue::new("resource.name", desc.resource.clone()),
                KeyValue::new("span.type", desc.span_type),
                KeyValue::new("operation.name", desc.operation),
                // "operation.name" is consumed into dd_span.name and stripped from meta.
                // "operation_name" (no dot) passes through to meta["operation_name"],
                // which is what Datadog APM reads as the span's operation name.
                KeyValue::new("operation_name", desc.operation),
                KeyValue::new("peer.service", desc.service.clone()),
            ];
            for (k, v) in &desc.tags {
                attrs.push(KeyValue::new(k.clone(), v.clone()));
            }
            builder.attributes = Some(attrs);

            let span = self.tracer.build_with_context(builder, &current_cx);
            current_cx = current_cx.with_span(span);
            span_contexts.push(current_cx.clone());
        }

        (current_cx, span_contexts, now)
    }
}

fn extract_from_headers(payload: &Value) -> Option<HashMap<String, String>> {
    let headers_locations = [
        payload.get("headers"),
        payload.get("request").and_then(|r| r.get("headers")),
    ];

    for headers_val in headers_locations.into_iter().flatten() {
        let Some(headers) = headers_val.as_object() else {
            continue;
        };

        if let Some(dd) = headers.get(CARRIER_KEY) {
            if let Some(carrier) = carrier_from_json_object(dd) {
                return Some(carrier);
            }
        }

        // Build a lowercase view of the header map so REST v1 events (which preserve
        // original client casing, e.g. "X-Datadog-Trace-Id") match the lowercase constants.
        let lower: HashMap<String, &Value> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();

        let mut carrier = HashMap::new();
        for key in [TRACE_ID_KEY, PARENT_ID_KEY, SAMPLING_PRIORITY_KEY, TAGS_KEY] {
            if let Some(val) = lower.get(key).and_then(|v| v.as_str()) {
                carrier.insert(key.to_owned(), val.to_owned());
            }
        }
        if carrier.contains_key(TRACE_ID_KEY) {
            return Some(carrier);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
    use opentelemetry::Value as OtelValue;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
    use serde_json::json;

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

    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<SpanData> {
        exporter.get_finished_spans().unwrap()
    }

    #[test]
    fn inferred_spans_set_expected_attributes() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let inferred = vec![InferredSpan {
            operation: "aws.sqs",
            trigger_source: "sqs",
            trigger_arn: None,
            service: "my-queue".to_string(),
            resource: "my-queue".to_string(),
            span_type: "web",
            start_time_ns: None,
            is_async: false,
            tags: HashMap::new(),
        }];

        let inferrer = SpanInferrer::new(&tracer);
        let (_, span_contexts, end_time) = inferrer.create_inferred_spans(&Context::current(), &inferred);
        for cx in span_contexts { cx.span().end_with_timestamp(end_time); }
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
            find_attr(attrs, "peer.service"),
            Some(&OtelValue::String("my-queue".into()))
        );
        assert_eq!(
            find_attr(attrs, "operation.name"),
            Some(&OtelValue::String("aws.sqs".into()))
        );
    }

    #[test]
    fn inferred_spans_are_chained() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let inferred = vec![
            InferredSpan {
                operation: "aws.sns",
                trigger_source: "sns",
                trigger_arn: None,
                service: "my-topic".to_string(),
                resource: "my-topic".to_string(),
                span_type: "web",
                start_time_ns: None,
                is_async: false,
                tags: HashMap::new(),
            },
            InferredSpan {
                operation: "aws.sqs",
                trigger_source: "sqs",
                trigger_arn: None,
                service: "my-queue".to_string(),
                resource: "my-queue".to_string(),
                span_type: "web",
                start_time_ns: None,
                is_async: false,
                tags: HashMap::new(),
            },
        ];

        let inferrer = SpanInferrer::new(&tracer);
        let (cx, span_contexts, end_time) = inferrer.create_inferred_spans(&Context::current(), &inferred);
        for sc in span_contexts { sc.span().end_with_timestamp(end_time); }
        provider.force_flush().ok();

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].name, "aws.sqs");
        assert_eq!(
            cx.span().span_context().span_id(),
            spans[1].span_context.span_id()
        );
    }

    #[test]
    fn infer_from_sqs_event() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let carrier_json = json!({
            "x-datadog-trace-id": "12345",
            "x-datadog-parent-id": "67890",
            "x-datadog-sampling-priority": "1"
        });
        let event = json!({
            "Records": [{
                "eventSource": "aws:sqs",
                "eventSourceARN": "arn:aws:sqs:us-east-1:123456789:test-queue",
                "awsRegion": "us-east-1",
                "body": "hello",
                "attributes": { "SentTimestamp": "1718444400000" },
                "messageAttributes": {
                    "_datadog": {
                        "stringValue": serde_json::to_string(&carrier_json).unwrap(),
                        "dataType": "String"
                    }
                }
            }]
        });

        let inferrer = SpanInferrer::new(&tracer);
        let result = inferrer.infer(&event);
        for cx in result.inferred_span_contexts { cx.span().end_with_timestamp(result.inferred_span_end_time); }
        provider.force_flush().ok();

        assert!(result.parent_cx.span().span_context().is_valid());
        assert!(result.is_async);

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name, "aws.sqs");
    }

    #[test]
    fn infer_from_http_headers() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");

        let event = json!({
            "headers": {
                "x-datadog-trace-id": "11111",
                "x-datadog-parent-id": "22222",
                "x-datadog-sampling-priority": "1"
            },
            "body": "some body"
        });

        let inferrer = SpanInferrer::new(&tracer);
        let result = inferrer.infer(&event);
        assert!(!result.is_async);
    }

    #[test]
    fn infer_from_request_headers() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");

        let event = json!({
            "request": {
                "headers": {
                    "x-datadog-trace-id": "33333",
                    "x-datadog-parent-id": "44444"
                }
            }
        });

        let inferrer = SpanInferrer::new(&tracer);
        let result = inferrer.infer(&event);
        assert!(!result.is_async);
    }

    #[test]
    fn infer_returns_default_when_no_context() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");

        let event = json!({ "key": "value" });
        let inferrer = SpanInferrer::new(&tracer);
        let result = inferrer.infer(&event);
        assert!(!result.is_async);
    }

    #[test]
    fn infer_returns_default_for_invalid_trace_id() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");

        let event = json!({
            "headers": {
                "x-datadog-trace-id": "0",
                "x-datadog-parent-id": "22222"
            }
        });

        let inferrer = SpanInferrer::new(&tracer);
        let result = inferrer.infer(&event);
        assert!(!result.is_async);
    }

    use crate::span_inferrer::triggers::test_utils::load_payload;

    #[test]
    fn api_gateway_rest_event_extracts_carrier() {
        let event = load_payload("api_gateway_rest_event.json");
        let carrier = extract_from_headers(&event).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
        assert_eq!(carrier.get(SAMPLING_PRIORITY_KEY).unwrap(), "1");
    }

    #[test]
    fn api_gateway_rest_event_capitalized_headers_extracts_carrier() {
        // REST v1 preserves original client header casing (e.g. "X-Datadog-Trace-Id").
        // Extraction must be case-insensitive.
        let event = load_payload("api_gateway_rest_event_capitalized.json");
        let carrier = extract_from_headers(&event).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
    }

    #[test]
    fn api_gateway_http_event_extracts_carrier() {
        // HTTP API v2 lowercases all headers — standard extraction path.
        let event = load_payload("api_gateway_http_event.json");
        let carrier = extract_from_headers(&event).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
    }

    #[test]
    fn api_gateway_no_carrier_returns_none() {
        let event = load_payload("api_gateway_rest_event_no_carrier.json");
        assert!(extract_from_headers(&event).is_none());
    }
}
