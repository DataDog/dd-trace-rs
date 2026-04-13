// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// NOTE: span_inferrer/triggers/ and span_inferrer/carrier/ are superseded by
// libdd-trace-inferrer. The triggers/ directory is kept for reference but is
// no longer compiled. carrier.rs is still used for the header fallback path.
pub(crate) mod carrier;

use crate::attribute_keys as attr;
use carrier::{validate_carrier, PARENT_ID_KEY, SAMPLING_PRIORITY_KEY, TAGS_KEY, TRACE_ID_KEY};
use libdd_trace_inferrer::{InferConfig, InferenceResult, SpanInferrer};
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Metadata extracted from the trigger event.
pub(crate) struct TriggerContext {
    /// OTel context whose active span is the innermost inferred span (or the extracted
    /// propagation context when there are no inferred spans).
    pub parent_cx: Context,
    pub is_async: bool,
    /// Short name of the outermost trigger, e.g. `"sqs"`.
    pub event_source: Option<String>,
    /// ARN of the outermost trigger resource.
    pub event_source_arn: Option<String>,
}

struct ActiveInferredSpan {
    cx: Context,
    is_async: bool,
}

/// Handle for the set of inferred spans created for a trigger.
pub(crate) struct InferredSpanScope {
    spans: Vec<ActiveInferredSpan>,
}

impl InferredSpanScope {
    pub(crate) fn empty() -> Self {
        Self { spans: Vec::new() }
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Build OTel inferred spans from an `InferenceResult`.
    ///
    /// Spans are created outer → inner so the innermost span is the direct
    /// parent of the Lambda invocation span. The returned `Context` has the
    /// innermost span active.
    pub(crate) fn start(
        tracer: &SdkTracer,
        parent_cx: &Context,
        result: &InferenceResult,
    ) -> (Context, Self) {
        if !result.should_create_inferred_span() {
            return (parent_cx.clone(), Self::empty());
        }

        // Collect the chain outer → inner.
        // wrapped_span (if present) is the outer/earlier span (e.g. SNS wrapping SQS).
        // result.span_data is the inner span (direct parent of aws.lambda).
        let mut chain: Vec<(&libdd_trace_inferrer::SpanData, bool)> = Vec::new();
        if let Some(ref wrapped) = result.wrapped_span {
            if wrapped.should_create_inferred_span() {
                chain.push((&wrapped.span_data, wrapped.is_async));
            }
        }
        chain.push((&result.span_data, result.is_async));

        let mut current_cx = parent_cx.clone();
        let mut active_spans = Vec::with_capacity(chain.len());

        for (span_data, is_async) in chain {
            let mut builder = tracer.span_builder(span_data.name.clone());
            builder.span_kind = Some(SpanKind::Server);

            let start_ns = u64::try_from(span_data.start).unwrap_or(0);
            if start_ns > 0 {
                builder.start_time =
                    Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(start_ns));
            }

            let mut attrs = vec![
                KeyValue::new(attr::SERVICE_NAME, span_data.service.clone()),
                KeyValue::new(attr::RESOURCE_NAME, span_data.resource.clone()),
                KeyValue::new(attr::SPAN_TYPE, span_data.r#type.clone()),
                KeyValue::new(attr::OPERATION_NAME, span_data.name.clone()),
                KeyValue::new(attr::OPERATION_NAME_CUSTOM, span_data.name.clone()),
                KeyValue::new(attr::PEER_SERVICE, span_data.service.clone()),
            ];
            for (k, v) in &span_data.meta {
                attrs.push(KeyValue::new(k.clone(), v.clone()));
            }
            builder.attributes = Some(attrs);

            let span = tracer.build_with_context(builder, &current_cx);
            current_cx = current_cx.with_span(span);
            active_spans.push(ActiveInferredSpan {
                cx: current_cx.clone(),
                is_async,
            });
        }

        (current_cx, Self { spans: active_spans })
    }

    /// End all inferred spans with correct timing.
    ///
    /// Async spans end at invocation start (propagation delay).
    /// Sync spans end at invocation end (full request duration).
    pub(crate) fn end(&self, invocation_start: SystemTime, invocation_end: SystemTime) {
        for span in &self.spans {
            let end_time = if span.is_async {
                invocation_start
            } else {
                invocation_end
            };
            span.cx.span().end_with_timestamp(end_time);
        }
    }
}

pub(crate) struct TriggerExtraction {
    pub upstream_cx: Context,
    pub inference_result: InferenceResult,
    pub is_async: bool,
    pub event_source: Option<String>,
    pub event_source_arn: Option<String>,
}

pub(crate) struct TriggerExtractor;

impl TriggerExtractor {
    pub(crate) fn extract(payload: &Value) -> TriggerExtraction {
        let config = InferConfig {
            region: std::env::var("AWS_REGION").unwrap_or_default(),
            ..InferConfig::default()
        };
        let inferrer = SpanInferrer::new(config);
        let result = inferrer.infer_span_from_value(payload);

        let event_source = result
            .trigger_tags
            .get("function_trigger.event_source")
            .cloned();
        let event_source_arn = result
            .trigger_tags
            .get("function_trigger.event_source_arn")
            .cloned();
        let is_async = result.is_async;

        // Try the carrier extracted by libdd-trace-inferrer first.
        if validate_carrier(&result.carrier).is_some() {
            tracing::debug!(
                trace_id = result
                    .carrier
                    .get(TRACE_ID_KEY)
                    .map(String::as_str)
                    .unwrap_or("?"),
                "extracted trace context from trigger"
            );
            let upstream_cx =
                global::get_text_map_propagator(|p| p.extract(&result.carrier));
            return TriggerExtraction {
                upstream_cx,
                inference_result: result,
                is_async,
                event_source,
                event_source_arn,
            };
        }

        // Fallback: raw header extraction for unrecognised payloads.
        if let Some(carrier) = extract_from_headers(payload) {
            if validate_carrier(&carrier).is_some() {
                tracing::debug!(
                    trace_id = carrier.get(TRACE_ID_KEY).map(String::as_str).unwrap_or("?"),
                    "extracted trace context from headers"
                );
                let upstream_cx =
                    global::get_text_map_propagator(|p| p.extract(&carrier));
                return TriggerExtraction {
                    upstream_cx,
                    inference_result: result,
                    is_async,
                    event_source,
                    event_source_arn,
                };
            }
        }

        tracing::debug!("no trace context found in event");
        TriggerExtraction {
            upstream_cx: Context::current(),
            inference_result: result,
            is_async,
            event_source,
            event_source_arn,
        }
    }
}

// ---------------------------------------------------------------------------
// Header fallback (for raw events that carry Datadog headers but don't match
// any known trigger shape).
// ---------------------------------------------------------------------------

use carrier::carrier_from_json_object;
use carrier::DATADOG_ATTRIBUTE_KEY;

fn extract_from_headers(payload: &Value) -> Option<HashMap<String, String>> {
    let headers_locations = [
        payload.get("headers"),
        payload.get("request").and_then(|r| r.get("headers")),
    ];

    for headers_val in headers_locations.into_iter().flatten() {
        let Some(headers) = headers_val.as_object() else {
            continue;
        };

        if let Some(dd) = headers.get(DATADOG_ATTRIBUTE_KEY) {
            if let Some(carrier) = carrier_from_json_object(dd) {
                return Some(carrier);
            }
        }

        let lower: HashMap<String, &Value> =
            headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();

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
    use libdd_trace_inferrer::{InferenceResult, SpanData};
    use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
    use opentelemetry::Value as OtelValue;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData as OtelSpanData};
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

    #[test]
    fn sets_expected_attributes_on_inferred_spans() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let result = make_result("aws.sqs", "my-queue");
        let (_, scope) = InferredSpanScope::start(&tracer, &Context::current(), &result);
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

        let (cx, scope) = InferredSpanScope::start(&tracer, &Context::current(), &result);
        let now = SystemTime::now();
        scope.end(now, now);
        provider.force_flush().ok();

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 2);
        // Innermost span (sqs) should be the active span in the returned context
        assert_eq!(
            cx.span().span_context().span_id(),
            spans.iter().find(|s| s.name == "aws.sqs").unwrap().span_context.span_id()
        );
    }

    #[test]
    fn preserves_parent_context_when_no_inferred_spans_are_created() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");
        let parent_cx = Context::current();
        let empty_result = InferenceResult::default();
        let (result_cx, scope) = InferredSpanScope::start(&tracer, &parent_cx, &empty_result);

        assert_eq!(
            result_cx.span().span_context().trace_id(),
            parent_cx.span().span_context().trace_id()
        );
        assert!(scope.spans.is_empty());
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

        let extraction = TriggerExtractor::extract(&event);

        assert!(extraction.is_async);
        assert_eq!(extraction.event_source.as_deref(), Some("sqs"));
        assert!(extraction.inference_result.should_create_inferred_span());
        assert_eq!(extraction.inference_result.span_data.name, "aws.sqs");
    }

    #[test]
    fn extracts_carrier_from_api_gateway_rest_event() {
        // REST v1 preserves original client header casing — extraction must be case-insensitive.
        let event = json!({
            "headers": {
                "X-Datadog-Trace-Id": "12345",
                "X-Datadog-Parent-Id": "67890",
                "X-Datadog-Sampling-Priority": "1"
            },
            "requestContext": {
                "stage": "prod",
                "httpMethod": "GET",
                "resourcePath": "/test"
            },
            "resource": "/test",
            "httpMethod": "GET"
        });
        let carrier = extract_from_headers(&event).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
    }
}
