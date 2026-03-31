// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod carrier;
mod triggers;

use crate::attribute_keys as attr;
use carrier::{
    carrier_from_json_object, validate_carrier, DATADOG_ATTRIBUTE_KEY, PARENT_ID_KEY,
    SAMPLING_PRIORITY_KEY, TAGS_KEY, TRACE_ID_KEY,
};
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Descriptor for an inferred span representing an AWS service trigger.
///
/// `wrapped_by` optionally points to an outer enclosing span (e.g. EventBridge wrapping SNS).
/// This span is the innermost — the direct parent of the Lambda invocation span.
pub(crate) struct InferredSpan {
    /// e.g. `"aws.sqs"`, `"aws.sns"`, `"aws.eventbridge"`
    pub operation: &'static str,
    /// e.g. `"sqs"`, `"sns"`, `"eventbridge"`
    pub trigger_source: &'static str,
    pub trigger_arn: Option<String>,
    /// ARN-based key to link inferred spans to AWS resources.
    pub dd_resource_key: Option<String>,
    pub service: String,
    pub resource: String,
    /// e.g. `"web"`, `"http"` (Lambda Function URL).
    pub span_type: &'static str,
    /// Nanoseconds since Unix epoch.
    pub start_time_ns: Option<i64>,
    pub is_async: bool,
    /// e.g. `source_arn`, `message_id`
    pub tags: HashMap<String, String>,
    /// Outer wrapping span, e.g. EventBridge wrapping SNS or SNS wrapping SQS.
    /// `Box` is required because the type is recursive.
    pub wrapped_by: Option<Box<InferredSpan>>,
}

impl InferredSpan {
    /// Returns the outermost span in the chain (the one with no `wrapped_by`).
    pub(crate) fn outermost(&self) -> &InferredSpan {
        let mut current = self;
        while let Some(ref outer) = current.wrapped_by {
            current = outer;
        }
        current
    }
}

/// Metadata extracted from the trigger event.
pub(crate) struct TriggerContext {
    /// OTel context whose active span is the innermost inferred span (or the extracted
    /// propagation context when there are no inferred spans).
    pub parent_cx: Context,
    pub is_async: bool,
    /// Short name of the outermost trigger, e.g. `"sqs"`.
    pub event_source: Option<&'static str>,
    /// ARN of the outermost trigger resource.
    pub event_source_arn: Option<String>,
}

struct ActiveInferredSpan {
    cx: Context,
    is_async: bool,
}

/// Handle for the set of inferred spans created for a trigger.
///
/// Spans are left open until `end()` is called so their durations cover only
/// the trigger propagation delay, not the handler execution time.
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

    // Spans are created outer to inner; the returned context's active span is the
    // innermost (direct parent of the invocation span).
    pub(crate) fn start(
        tracer: &SdkTracer,
        parent_cx: &Context,
        inferred: Option<&InferredSpan>,
    ) -> (Context, Self) {
        let Some(innermost) = inferred else {
            return (parent_cx.clone(), Self::empty());
        };

        // Collect the chain from outermost to innermost.
        let mut chain: Vec<&InferredSpan> = Vec::new();
        let mut current = innermost;
        loop {
            chain.push(current);
            if let Some(ref outer) = current.wrapped_by {
                current = outer;
            } else {
                break;
            }
        }
        chain.reverse(); // now outer → inner

        let mut current_cx = parent_cx.clone();
        let mut active_spans = Vec::with_capacity(chain.len());

        for desc in chain {
            let mut builder = tracer.span_builder(desc.operation);
            builder.span_kind = Some(SpanKind::Server);
            if let Some(start_ns) = desc.start_time_ns {
                let start_ns = u64::try_from(start_ns).unwrap_or(0);
                builder.start_time = Some(SystemTime::UNIX_EPOCH + Duration::from_nanos(start_ns));
            }
            let mut attrs = vec![
                KeyValue::new(attr::SERVICE_NAME, desc.service.clone()),
                KeyValue::new(attr::RESOURCE_NAME, desc.resource.clone()),
                KeyValue::new(attr::SPAN_TYPE, desc.span_type),
                KeyValue::new(attr::OPERATION_NAME, desc.operation),
                KeyValue::new(attr::OPERATION_NAME_CUSTOM, desc.operation),
                KeyValue::new(attr::PEER_SERVICE, desc.service.clone()),
            ];
            if let Some(ref key) = desc.dd_resource_key {
                attrs.push(KeyValue::new(attr::DD_RESOURCE_KEY, key.clone()));
            }
            for (k, v) in &desc.tags {
                attrs.push(KeyValue::new(k.clone(), v.clone()));
            }
            builder.attributes = Some(attrs);

            let span = tracer.build_with_context(builder, &current_cx);
            current_cx = current_cx.with_span(span);
            active_spans.push(ActiveInferredSpan {
                cx: current_cx.clone(),
                is_async: desc.is_async,
            });
        }

        (
            current_cx,
            Self {
                spans: active_spans,
            },
        )
    }

    /// End all inferred spans with correct timing relative to the Lambda invocation.
    ///
    /// Async spans (SQS, SNS, Kinesis) end at invocation start — they represent propagation
    /// delay before the Lambda began executing. Sync spans (API Gateway, ALB) end at invocation
    /// end, consistent with the Datadog Lambda extension behavior.
    ///
    /// Must be called after the root span is created so all spans are exported in the same flush.
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
    pub inferred_span: Option<InferredSpan>,
    pub is_async: bool,
    pub event_source: Option<&'static str>,
    pub event_source_arn: Option<String>,
}

pub(crate) struct TriggerExtractor;

impl TriggerExtractor {
    pub(crate) fn extract(payload: &Value) -> TriggerExtraction {
        if let Some(result) = triggers::extract(payload) {
            let is_async = result
                .inferred_span
                .as_ref()
                .map(|s| s.is_async)
                .unwrap_or(false);
            let upstream_cx = if validate_carrier(&result.carrier).is_some() {
                tracing::debug!(
                    trace_id = result
                        .carrier
                        .get(TRACE_ID_KEY)
                        .map(String::as_str)
                        .unwrap_or("?"),
                    "extracted trace context from trigger"
                );
                global::get_text_map_propagator(|p| p.extract(&result.carrier))
            } else {
                tracing::debug!("trigger recognized, no upstream trace context");
                Context::current()
            };
            return TriggerExtraction {
                upstream_cx,
                inferred_span: result.inferred_span,
                is_async,
                event_source: Some(result.event_source),
                event_source_arn: result.event_source_arn,
            };
        }

        if let Some(carrier) = extract_from_headers(payload) {
            if validate_carrier(&carrier).is_some() {
                tracing::debug!(
                    trace_id = carrier.get(TRACE_ID_KEY).map(String::as_str).unwrap_or("?"),
                    "extracted trace context from headers"
                );
                let extracted_cx = global::get_text_map_propagator(|p| p.extract(&carrier));
                return TriggerExtraction {
                    upstream_cx: extracted_cx,
                    inferred_span: None,
                    is_async: false,
                    event_source: None,
                    event_source_arn: None,
                };
            }
        }

        tracing::debug!("no trace context found in event");
        TriggerExtraction {
            upstream_cx: Context::current(),
            inferred_span: None,
            is_async: false,
            event_source: None,
            event_source_arn: None,
        }
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

        if let Some(dd) = headers.get(DATADOG_ATTRIBUTE_KEY) {
            if let Some(carrier) = carrier_from_json_object(dd) {
                return Some(carrier);
            }
        }

        // Build a lowercase view of the header map so REST v1 events (which preserve
        // original client casing, e.g. "X-Datadog-Trace-Id") match the lowercase constants.
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
    use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
    use opentelemetry::Value as OtelValue;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
    use serde_json::json;
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

    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<SpanData> {
        exporter.get_finished_spans().unwrap()
    }

    #[test]
    fn sets_expected_attributes_on_inferred_spans() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let inferred = InferredSpan {
            operation: "aws.sqs",
            trigger_source: "sqs",
            trigger_arn: None,
            dd_resource_key: None,
            service: "my-queue".to_string(),
            resource: "my-queue".to_string(),
            span_type: "web",
            start_time_ns: None,
            is_async: false,
            tags: HashMap::new(),
            wrapped_by: None,
        };

        let (_, scope) = InferredSpanScope::start(&tracer, &Context::current(), Some(&inferred));
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
            find_attr(attrs, "peer.service"),
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

        let inferred = InferredSpan {
            operation: "aws.sqs",
            trigger_source: "sqs",
            trigger_arn: None,
            dd_resource_key: None,
            service: "my-queue".to_string(),
            resource: "my-queue".to_string(),
            span_type: "web",
            start_time_ns: None,
            is_async: false,
            tags: HashMap::new(),
            wrapped_by: Some(Box::new(InferredSpan {
                operation: "aws.sns",
                trigger_source: "sns",
                trigger_arn: None,
                dd_resource_key: None,
                service: "my-topic".to_string(),
                resource: "my-topic".to_string(),
                span_type: "web",
                start_time_ns: None,
                is_async: false,
                tags: HashMap::new(),
                wrapped_by: None,
            })),
        };

        let (cx, scope) = InferredSpanScope::start(&tracer, &Context::current(), Some(&inferred));
        let now = SystemTime::now();
        scope.end(now, now);
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
    fn preserves_parent_context_when_no_inferred_spans_are_created() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");
        let parent_cx = Context::current();
        let (result_cx, scope) = InferredSpanScope::start(&tracer, &parent_cx, None);

        assert_eq!(
            result_cx.span().span_context().trace_id(),
            parent_cx.span().span_context().trace_id()
        );
        assert_eq!(
            result_cx.span().span_context().span_id(),
            parent_cx.span().span_context().span_id()
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

        let result = TriggerExtractor::extract(&event);

        assert!(result.is_async);
        assert_eq!(result.event_source, Some("sqs"));
        assert_eq!(
            result.event_source_arn.as_deref(),
            Some("arn:aws:sqs:us-east-1:123456789:test-queue")
        );
        assert_eq!(result.inferred_span.as_ref().unwrap().operation, "aws.sqs");
    }

    use crate::span_inferrer::triggers::test_utils::load_payload;

    #[test]
    fn extracts_carrier_from_api_gateway_rest_event() {
        let event = load_payload("api_gateway_rest_event_inferred.json");
        let carrier = extract_from_headers(&event).unwrap();
        assert_eq!(carrier.get(TRACE_ID_KEY).unwrap(), "12345");
        assert_eq!(carrier.get(PARENT_ID_KEY).unwrap(), "67890");
        assert_eq!(carrier.get(SAMPLING_PRIORITY_KEY).unwrap(), "1");
    }

    #[test]
    fn extracts_carrier_from_api_gateway_rest_event_with_capitalized_headers() {
        // REST v1 preserves original client header casing (e.g. "X-Datadog-Trace-Id").
        // Extraction must be case-insensitive.
        let event = load_payload("api_gateway_rest_event_capitalized.json");
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
