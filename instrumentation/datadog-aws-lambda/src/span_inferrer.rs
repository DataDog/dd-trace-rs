// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Bridge between [`crate::inference`] and the OpenTelemetry SDK.
//!
//! Responsibilities:
//! - Parse the raw Lambda event payload with `crate::inference` to identify the trigger type and
//!   extract span metadata and carrier headers.
//! - Convert the inferred [`SpanData`](crate::inference::SpanData) into live OTel spans using the
//!   Datadog tracer.
//! - Expose [`TriggerContext`] so [`crate::invocation`] can parent the root span correctly.

use crate::attribute_keys as attr;
use crate::inference::{InferConfig, InferenceResult, SpanInferrer};

use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::propagation::DatadogPropagator;
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Builds the inferrer from the tracer configuration and the Lambda runtime environment.
#[allow(clippy::disallowed_methods)]
pub(crate) fn build_inferrer(config: &Config) -> SpanInferrer {
    SpanInferrer::new(InferConfig {
        region: std::env::var("AWS_REGION").unwrap_or_default(),
        function_name: std::env::var("AWS_LAMBDA_FUNCTION_NAME").unwrap_or_default(),
        service_mapping: config
            .service_mapping()
            .map(|(from, to)| (from.to_string(), to.to_string()))
            .collect(),
        aws_service_representation_enabled: config.trace_aws_service_representation_enabled(),
    })
}

#[cfg(test)]
pub(crate) fn default_inferrer() -> SpanInferrer {
    build_inferrer(&Config::builder().build())
}

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
    /// Tags of the trigger that invoked the function, such as `function_trigger.event_source`
    /// and HTTP request metadata. Added to the root span.
    pub trigger_tags: HashMap<String, String>,
}

/// An inferred span that is currently open, held as an OTel context.
struct ActiveInferredSpan {
    /// OTel context whose active span is this inferred span.
    cx: Context,
    /// Mirrors [`TriggerContext::is_async`] — determines the end-time passed to
    /// [`InferredSpanScope::end`].
    is_async: bool,
    /// Start time recorded on this inferred span.
    start_time: SystemTime,
}

/// Handle for the set of inferred spans created for a trigger.
pub(crate) struct InferredSpanScope {
    outer: Option<Context>,
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
    ///
    /// When an event time is unknown, the inner span starts at `invocation_start` and a wrapped
    /// outer span starts when the inner span starts, so neither ends before it starts.
    pub(crate) fn start(
        tracer: &SdkTracer,
        parent_cx: &Context,
        result: &InferenceResult,
        invocation_start: SystemTime,
    ) -> Self {
        let Some(span_data) = &result.span_data else {
            return Self::empty();
        };

        let inner_start = inferred_span_start_time(span_data).unwrap_or(invocation_start);
        let mut current_cx = parent_cx.clone();

        let outer = result.wrapped_span.as_ref().map(|wrapped| {
            let start_time = inferred_span_start_time(wrapped).unwrap_or(inner_start);
            current_cx = build_inferred_span(tracer, wrapped, &current_cx, start_time);
            current_cx.clone()
        });

        current_cx = build_inferred_span(tracer, span_data, &current_cx, inner_start);
        let inner = Some(ActiveInferredSpan {
            cx: current_cx,
            is_async: result.is_async,
            start_time: inner_start,
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
                .map_or(invocation_start, |inner| inner.start_time);
            outer.span().end_with_timestamp(outer_end_time);
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

fn inferred_span_start_time(span_data: &crate::inference::SpanData) -> Option<SystemTime> {
    let start_ns = u64::try_from(span_data.start).ok()?;
    (start_ns > 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_nanos(start_ns))
}

/// Converts a [`crate::inference::SpanData`] into a live OTel span.
///
/// Returns a new OTel context with the new span as the active span. All metadata
/// from `span_data.meta` is added as span attributes.
fn build_inferred_span(
    tracer: &SdkTracer,
    span_data: &crate::inference::SpanData,
    parent_cx: &Context,
    start_time: SystemTime,
) -> Context {
    let mut builder = tracer.span_builder(span_data.name.clone());
    builder.span_kind = Some(SpanKind::Server);
    builder.start_time = Some(start_time);

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
    /// Full inference result from `crate::inference`, including span data, trigger
    /// tags, and async/sync classification.
    pub inference_result: InferenceResult,
}

/// Infers trigger metadata from `payload` and extracts the upstream OTel context.
///
/// Carriers are interpreted by `propagator` with the configured styles, including W3C headers.
/// It is used instead of the global propagator so event-derived context is never dropped.
pub(crate) fn extract_trigger(
    inferrer: &SpanInferrer,
    propagator: &DatadogPropagator,
    payload: &str,
) -> TriggerExtraction {
    let result = inferrer.infer_span(payload).unwrap_or_default();
    let upstream_cx = extract_upstream_context(propagator, &result, &Context::current());

    TriggerExtraction {
        upstream_cx,
        inference_result: result,
    }
}

fn extract_upstream_context(
    propagator: &DatadogPropagator,
    result: &InferenceResult,
    ambient: &Context,
) -> Context {
    propagator.extract_with_fallback(ambient, &result.carrier, result.generated_context.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::triggers::test_utils::read_json_file;
    use crate::inference::{InferenceResult, SpanData};
    use datadog_opentelemetry::configuration::TracePropagationStyle;
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
    use opentelemetry::Value as OtelValue;
    use opentelemetry_sdk::trace::{
        InMemorySpanExporter, SdkTracerProvider, SpanData as OtelSpanData,
    };
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

    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<OtelSpanData> {
        exporter.get_finished_spans().unwrap()
    }

    fn make_result(name: &str, service: &str) -> InferenceResult {
        InferenceResult {
            span_data: Some(SpanData {
                name: name.to_string(),
                service: service.to_string(),
                resource: service.to_string(),
                r#type: "web".to_string(),
                start: 0,
                meta: HashMap::new(),
            }),
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
        let now = SystemTime::now();
        let scope = InferredSpanScope::start(&tracer, &Context::current(), &result, now);
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
        result.wrapped_span = make_result("aws.sns", "my-topic").span_data;

        let parent_cx = Context::current();
        let now = SystemTime::now();
        let scope = InferredSpanScope::start(&tracer, &parent_cx, &result, now);
        let cx = scope.innermost_context(&parent_cx);
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
        result.span_data.as_mut().unwrap().start = inner_start_ns as i64;
        result.is_async = true;

        let mut wrapped = make_result("aws.sns", "my-topic");
        wrapped.span_data.as_mut().unwrap().start = outer_start_ns as i64;
        result.wrapped_span = wrapped.span_data;

        let scope =
            InferredSpanScope::start(&tracer, &Context::current(), &result, invocation_start);
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
        let scope = InferredSpanScope::start(&tracer, &parent_cx, &empty_result, SystemTime::now());
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

        let (_dd_provider, propagator) = test_propagator();
        let inferrer = default_inferrer();
        let extraction = extract_trigger(&inferrer, &propagator, &event.to_string());

        assert!(extraction.inference_result.is_async);
        assert_eq!(
            extraction
                .inference_result
                .trigger_tags
                .get("function_trigger.event_source")
                .map(String::as_str),
            Some("sqs")
        );
        assert!(extraction.inference_result.span_data.is_some());
        assert_eq!(
            extraction.inference_result.span_data.as_ref().unwrap().name,
            "aws.sqs"
        );
    }

    fn infer_fixture(name: &str) -> InferenceResult {
        let inferrer = SpanInferrer::new(InferConfig {
            region: "us-east-1".into(),
            ..Default::default()
        });
        inferrer.infer_span(&read_json_file(name)).unwrap()
    }

    fn test_propagator() -> (SdkTracerProvider, DatadogPropagator) {
        let mut config = datadog_opentelemetry::configuration::Config::builder();
        config.set_trace_propagation_style(vec![
            datadog_opentelemetry::configuration::TracePropagationStyle::Datadog,
            datadog_opentelemetry::configuration::TracePropagationStyle::TraceContext,
        ]);
        datadog_opentelemetry::tracing()
            .with_config(config.build())
            .init_local()
    }

    #[test]
    fn default_inference_preserves_resource_service_names() {
        let result = infer_fixture("sqs_event.json");
        assert_eq!(result.span_data.as_ref().unwrap().service, "MyQueue");
    }

    #[test]
    fn bottlecap_fixtures_create_parent_spans_with_event_timestamps() {
        let (_dd_provider, propagator) = test_propagator();
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");
        let invocation_start = nanos_to_system_time(1_900_000_000_000_000_000);
        let invocation_end = invocation_start + Duration::from_secs(1);
        for (fixture, name, is_async) in [
            ("api_gateway_http_event.json", "aws.httpapi", false),
            ("api_gateway_rest_event.json", "aws.apigateway", false),
            (
                "api_gateway_websocket_connect_event.json",
                "aws.apigateway",
                true,
            ),
            ("lambda_function_url_event.json", "aws.lambda.url", false),
            ("sqs_event.json", "aws.sqs", true),
            ("sns_event.json", "aws.sns", true),
            ("eventbridge_event.json", "aws.eventbridge", true),
            ("kinesis_event.json", "aws.kinesis", true),
            ("dynamodb_event.json", "aws.dynamodb", true),
            ("s3_event.json", "aws.s3", true),
            ("msk_event_with_headers.json", "aws.msk", true),
        ] {
            let result = infer_fixture(fixture);
            assert_eq!(result.span_data.as_ref().unwrap().name, name, "{fixture}");
            assert_eq!(result.is_async, is_async, "{fixture}");
            let upstream = extract_upstream_context(&propagator, &result, &Context::new());
            let scope = InferredSpanScope::start(&tracer, &upstream, &result, invocation_start);
            let parent = scope.innermost_context(&upstream);
            let root = tracer.start_with_context("aws.lambda", &parent);
            let root_context = Context::new().with_span(root);
            scope.end(invocation_start, invocation_end);
            root_context.span().end();

            let spans = finished_spans(&exporter);
            let inferred = &spans[0];
            let root = &spans[1];
            assert_eq!(
                inferred.start_time,
                inferred_span_start_time(result.span_data.as_ref().unwrap()).unwrap()
            );
            assert_eq!(
                inferred.end_time,
                if is_async {
                    invocation_start
                } else {
                    invocation_end
                }
            );
            assert_eq!(root.parent_span_id, inferred.span_context.span_id());
            assert_eq!(
                root.span_context.trace_id(),
                inferred.span_context.trace_id()
            );
            if upstream.span().span_context().is_valid() {
                assert_eq!(
                    inferred.parent_span_id,
                    upstream.span().span_context().span_id()
                );
                assert_eq!(
                    inferred.span_context.trace_id(),
                    upstream.span().span_context().trace_id()
                );
            }
            assert_eq!(
                find_attr(&inferred.attributes, "_inferred_span.tag_source"),
                Some(&OtelValue::String("self".into()))
            );
            exporter.reset();
        }
    }

    #[test]
    fn wrapped_events_preserve_carrier_parentage_and_queue_timing() {
        let (_dd_provider, propagator) = test_propagator();
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");
        for (fixture, outer_name, inner_name) in [
            ("sns_sqs_event.json", "aws.sns", "aws.sqs"),
            ("sns_sqs_binary_event.json", "aws.sns", "aws.sqs"),
            ("eventbridge_sqs_event.json", "aws.eventbridge", "aws.sqs"),
            ("eventbridge_sns_event.json", "aws.eventbridge", "aws.sns"),
        ] {
            let result = infer_fixture(fixture);
            let upstream = extract_upstream_context(&propagator, &result, &Context::new());
            assert!(upstream.span().span_context().is_valid(), "{fixture}");
            let now = SystemTime::now();
            let scope = InferredSpanScope::start(&tracer, &upstream, &result, now);
            scope.end(now, now);
            let spans = finished_spans(&exporter);
            assert_eq!(spans.len(), 2, "{fixture}");
            let outer = &spans[0];
            let inner = &spans[1];
            assert_eq!(outer.name, outer_name);
            assert_eq!(inner.name, inner_name);
            assert_eq!(
                outer.parent_span_id,
                upstream.span().span_context().span_id()
            );
            assert_eq!(inner.parent_span_id, outer.span_context.span_id());
            assert_eq!(
                inner.span_context.trace_id(),
                upstream.span().span_context().trace_id()
            );
            assert_eq!(outer.end_time, inner.start_time);
            exporter.reset();
        }
    }

    #[test]
    fn w3c_only_event_headers_continue_the_upstream_trace() {
        let (_dd_provider, propagator) = test_propagator();
        let mut event: serde_json::Value =
            serde_json::from_str(&read_json_file("api_gateway_http_event.json")).unwrap();
        event["headers"] =
            json!({"traceparent": "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"});
        let result = default_inferrer().infer_span(&event.to_string()).unwrap();
        let upstream = extract_upstream_context(&propagator, &result, &Context::new());
        assert_eq!(
            upstream.span().span_context().trace_id().to_string(),
            "1234567890abcdef1234567890abcdef"
        );
        assert_eq!(
            upstream.span().span_context().span_id().to_string(),
            "1234567890abcdef"
        );
    }

    #[test]
    fn step_functions_generate_128_bit_context_without_a_service_span() {
        let (_dd_provider, propagator) = test_propagator();
        for fixture in [
            "step_function_event.json",
            "step_function_legacy_event.json",
            "step_function_nested_event.json",
            "step_function_nested_legacy_event.json",
            "step_function_lambda_root_event.json",
            "step_function_lambda_root_legacy_event.json",
        ] {
            let result = infer_fixture(fixture);
            assert!(result.span_data.is_none(), "{fixture}");
            assert_eq!(
                result.trigger_tags["function_trigger.event_source"],
                "states"
            );
            let upstream = extract_upstream_context(&propagator, &result, &Context::new());
            let span = upstream.span();
            let context = span.span_context();
            assert!(context.is_valid(), "{fixture}");
            assert_eq!(
                context.trace_id().to_string(),
                format!(
                    "{:032x}",
                    result.generated_context.as_ref().unwrap().trace_id
                )
            );
            assert!(u128::from_be_bytes(context.trace_id().to_bytes()) > u128::from(u64::MAX));
            assert!(context.is_sampled());
            let invocation = _dd_provider
                .tracer("test")
                .start_with_context("aws.lambda", &upstream);
            let invocation_cx = upstream.with_span(invocation);
            let mut injected = HashMap::new();
            propagator.inject_context(&invocation_cx, &mut injected);
            invocation_cx.span().end();
            assert_eq!(injected["x-datadog-origin"], "states");
        }
    }

    #[test]
    fn step_functions_keep_leading_zero_high_trace_bits() {
        let mut event: serde_json::Value =
            serde_json::from_str(&read_json_file("step_function_event.json")).unwrap();
        event["Execution"]["Id"] =
            json!("arn:aws:states:us-east-1:425362996713:execution:agocsTestSF:regression-3");
        let result = default_inferrer().infer_span(&event.to_string()).unwrap();
        assert_eq!(
            result.generated_context.as_ref().unwrap().tags["_dd.p.tid"],
            "0a2cd4ab2e2818c4"
        );
        let (provider, propagator) = test_propagator();
        let upstream = extract_upstream_context(&propagator, &result, &Context::new());
        assert_eq!(
            upstream.span().span_context().trace_id().to_string(),
            "0a2cd4ab2e2818c46eed62ec038b1422"
        );
        let invocation = provider
            .tracer("test")
            .start_with_context("aws.lambda", &upstream);
        let cx = upstream.with_span(invocation);
        let mut carrier = HashMap::new();
        propagator.inject_context(&cx, &mut carrier);
        cx.span().end();
        let roundtrip = propagator.extract_with_context(&Context::new(), &carrier);
        assert_eq!(
            roundtrip.span().span_context().trace_id(),
            cx.span().span_context().trace_id()
        );
    }

    #[test]
    fn sqs_xray_sampling_preserves_local_and_upstream_decisions() {
        for styles in [
            vec![TracePropagationStyle::TraceContext],
            vec![
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::Datadog,
            ],
            vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ],
        ] {
            for (header, flags, sampled) in [
                (
                    "Root=1-64cc2edd-112fbf1701d1355973a11d57;Parent=7d5a9776024b2d42;Sampled=0",
                    2,
                    true,
                ),
                (
                    "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac",
                    2,
                    true,
                ),
                (
                    "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac;Sampled=0",
                    0,
                    false,
                ),
                (
                    "Root=1-68029e8a-0000000035578e774943fd9d;Parent=76c040bdc454a7ac;Sampled=1",
                    1,
                    true,
                ),
            ] {
                let (provider, propagator) = datadog_opentelemetry::tracing()
                    .with_config(
                        Config::builder()
                            .set_trace_propagation_style(styles.clone())
                            .set_trace_sample_rate(1.0)
                            .build(),
                    )
                    .init_local();
                let mut event: serde_json::Value =
                    serde_json::from_str(&read_json_file("sqs_event.json")).unwrap();
                event["Records"][0]["messageAttributes"] = json!({});
                event["Records"][0]["attributes"]["AWSTraceHeader"] = json!(header);
                let result = default_inferrer().infer_span(&event.to_string()).unwrap();
                let upstream = extract_upstream_context(&propagator, &result, &Context::new());
                assert_eq!(
                    upstream.span().span_context().trace_flags().to_u8(),
                    flags,
                    "{styles:?}: {header}"
                );
                let span = provider
                    .tracer("test")
                    .start_with_context("aws.lambda", &upstream);
                let cx = upstream.with_span(span);
                assert_eq!(
                    cx.span().span_context().is_sampled(),
                    sampled,
                    "{styles:?}: {header}"
                );
                assert_eq!(
                    cx.span().span_context().trace_id(),
                    upstream.span().span_context().trace_id()
                );
                cx.span().end();
            }
        }
    }

    #[test]
    fn s3_removals_without_object_metadata_still_create_spans() {
        for name in ["ObjectRemoved:Delete", "ObjectRemoved:DeleteMarkerCreated"] {
            let mut event: serde_json::Value =
                serde_json::from_str(&read_json_file("s3_event.json")).unwrap();
            event["Records"][0]["eventName"] = json!(name);
            let object = event["Records"][0]["s3"]["object"].as_object_mut().unwrap();
            object.remove("size");
            object.remove("eTag");
            let result = default_inferrer().infer_span(&event.to_string()).unwrap();
            let span_data = result.span_data.as_ref().unwrap();
            assert_eq!(span_data.name, "aws.s3");
            assert_eq!(span_data.meta["event_name"], name);
            assert!(!span_data.meta.contains_key("object_size"));
            assert!(!span_data.meta.contains_key("object_etag"));
            assert_eq!(
                result.trigger_tags["function_trigger.event_source_arn"],
                "arn:aws:s3:::example-bucket"
            );
        }
    }

    #[test]
    fn sqs_explicit_headers_take_precedence_over_aws_trace_header() {
        let (_dd_provider, propagator) = test_propagator();
        let mut event: serde_json::Value =
            serde_json::from_str(&read_json_file("sqs_event.json")).unwrap();
        event["Records"][0]["attributes"]["AWSTraceHeader"] =
            json!("Root=1-65e9fe55-00000000000000000000002a;Parent=000000000000002b;Sampled=0");
        let inferrer = default_inferrer();
        let result = inferrer.infer_span(&event.to_string()).unwrap();
        let upstream = extract_upstream_context(&propagator, &result, &Context::new());
        assert_eq!(
            u128::from_be_bytes(upstream.span().span_context().trace_id().to_bytes()),
            2_684_756_524_522_091_840
        );

        event["Records"][0]["messageAttributes"] = json!({});
        let result = inferrer.infer_span(&event.to_string()).unwrap();
        let upstream = extract_upstream_context(&propagator, &result, &Context::new());
        assert_eq!(
            u128::from_be_bytes(upstream.span().span_context().trace_id().to_bytes()),
            42
        );
        assert_eq!(
            upstream.span().span_context().span_id(),
            opentelemetry::SpanId::from(43)
        );
        assert!(!upstream.span().span_context().is_sampled());
    }

    #[test]
    fn alb_propagates_context_without_an_inferred_span() {
        let (_dd_provider, propagator) = test_propagator();
        let mut event: serde_json::Value =
            serde_json::from_str(&read_json_file("application_load_balancer.json")).unwrap();
        event["headers"] = json!({"X-Datadog-Trace-Id": "42", "X-Datadog-Parent-Id": "43"});
        let result = default_inferrer().infer_span(&event.to_string()).unwrap();
        assert!(result.span_data.is_none());
        assert!(!result.is_async);
        let upstream = extract_upstream_context(&propagator, &result, &Context::new());
        assert_eq!(
            u128::from_be_bytes(upstream.span().span_context().trace_id().to_bytes()),
            42
        );
    }

    #[test]
    fn malformed_or_unknown_payloads_leave_the_ambient_context_intact() {
        let (provider, _) = test_provider();
        let ambient = Context::new().with_span(provider.tracer("test").start("ambient"));
        let (_dd_provider, propagator) = test_propagator();
        for payload in [
            "null",
            "{}",
            "{",
            r#"{"Records": []}"#,
            r#"{"Records": [{"eventSource": "aws:sqs"}]}"#,
        ] {
            let result = default_inferrer().infer_span(payload).unwrap_or_default();
            assert!(result.span_data.is_none(), "{payload}");
            let upstream = extract_upstream_context(&propagator, &result, &ambient);
            assert_eq!(
                upstream.span().span_context(),
                ambient.span().span_context()
            );
        }
    }

    #[test]
    fn unknown_event_times_never_end_before_they_start() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");
        let invocation_start = nanos_to_system_time(10_000_000_000);
        let invocation_end = nanos_to_system_time(20_000_000_000);

        for (is_async, inner_start_ns, expected_inner, expected_inner_end) in [
            (true, 0, invocation_start, invocation_start),
            (false, 0, invocation_start, invocation_end),
            (
                true,
                2_000_000_000,
                nanos_to_system_time(2_000_000_000),
                invocation_start,
            ),
        ] {
            let mut result = make_result("aws.sqs", "my-queue");
            result.span_data.as_mut().unwrap().start = inner_start_ns;
            result.is_async = is_async;
            result.wrapped_span = make_result("aws.sns", "my-topic").span_data;

            let scope =
                InferredSpanScope::start(&tracer, &Context::current(), &result, invocation_start);
            scope.end(invocation_start, invocation_end);

            let spans = finished_spans(&exporter);
            let outer = spans.iter().find(|s| s.name == "aws.sns").unwrap();
            let inner = spans.iter().find(|s| s.name == "aws.sqs").unwrap();
            assert_eq!(inner.start_time, expected_inner, "{inner_start_ns}");
            assert_eq!(inner.end_time, expected_inner_end, "{inner_start_ns}");
            assert_eq!(outer.start_time, expected_inner, "{inner_start_ns}");
            assert_eq!(outer.end_time, expected_inner, "{inner_start_ns}");
            exporter.reset();
        }
    }

    #[test]
    fn inferrer_uses_service_mapping_and_representation_config() {
        let sqs_service = |inferrer: &SpanInferrer| {
            inferrer
                .infer_span(&read_json_file("sqs_event.json"))
                .unwrap()
                .span_data
                .unwrap()
                .service
        };
        assert_eq!(sqs_service(&default_inferrer()), "MyQueue");

        let mut config = Config::builder();
        config.set_trace_aws_service_representation_enabled(false);
        assert_eq!(sqs_service(&build_inferrer(&config.build())), "sqs");

        config.set_service_mapping(vec![("lambda_sqs".into(), "orders-queue".into())]);
        assert_eq!(
            sqs_service(&build_inferrer(&config.build())),
            "orders-queue"
        );
    }

    #[test]
    fn extraction_does_not_depend_on_the_global_propagator() {
        // Replacing the global propagator must not drop event-derived context.
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let (_dd_provider, propagator) = test_propagator();
        let extraction = extract_trigger(
            &default_inferrer(),
            &propagator,
            &read_json_file("step_function_event.json"),
        );
        assert!(extraction.upstream_cx.span().span_context().is_valid());
    }
}
