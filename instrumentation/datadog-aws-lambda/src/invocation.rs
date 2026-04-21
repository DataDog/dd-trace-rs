// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Lifecycle management for a single Lambda invocation.
//!
//! Each invocation produces:
//! - Zero or more *inferred spans* derived from the trigger payload (e.g., an SQS span)
//! - One *root span* (`aws.lambda`) that wraps the handler call
//!
//! Typical usage:
//! 1. [`Invocation::start`] — create all spans before the handler runs.
//! 2. [`Invocation::handler_context`] — pass the returned context to the handler so its OTel spans
//!    are correctly parented.
//! 3. [`Invocation::finish`] — record errors and end all spans after the handler returns.

use crate::attribute_keys as attr;
use crate::span_inferrer::{extract_trigger, InferredSpanScope, TriggerContext};
use libdd_trace_inferrer::SpanInferrer;

use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;
use std::time::SystemTime;

pub(crate) static TRACER_NAME: &str = "datadog-lambda-rs";
pub(crate) const ROOT_SPAN_NAME: &str = "aws.lambda";

/// The Lambda invocation (`aws.lambda`) root span.
///
/// Wraps the OTel context so the span can be ended via [`finish`](Self::finish)
/// and errors can be recorded via [`set_error`](Self::set_error).
pub(crate) struct LambdaSpan {
    /// OTel context whose active span is the `aws.lambda` root span.
    cx: Context,
    /// Lambda request ID, copied here for structured log correlation.
    request_id: String,
}

impl LambdaSpan {
    /// Creates and starts the `aws.lambda` root span.
    ///
    /// The span is parented to `trigger.parent_cx` when that context contains a valid
    /// span (i.e., a propagated or inferred upstream span exists). Otherwise it falls
    /// back to the ambient OTel context, which is typically a new root trace.
    pub(crate) fn start(
        tracer: &SdkTracer,
        trigger: &TriggerContext,
        lambda_cx: &lambda_runtime::Context,
        cold_start: bool,
    ) -> Self {
        let function_name = &lambda_cx.env_config.function_name;
        let request_id = lambda_cx.request_id.clone();

        tracing::debug!(request_id, "creating invocation root span");

        let effective_cx = if trigger.parent_cx.span().span_context().is_valid() {
            trigger.parent_cx.clone()
        } else {
            Context::current()
        };

        let mut builder = tracer.span_builder(ROOT_SPAN_NAME);
        builder.span_kind = Some(SpanKind::Server);
        let mut attrs = vec![
            KeyValue::new(attr::OPERATION_NAME, ROOT_SPAN_NAME),
            KeyValue::new(attr::LANGUAGE, "rust"),
            KeyValue::new(attr::RESOURCE_NAME, function_name.clone()),
            KeyValue::new(attr::SPAN_TYPE, "serverless"),
            KeyValue::new(attr::REQUEST_ID, request_id.clone()),
            KeyValue::new(attr::COLD_START, cold_start),
            KeyValue::new(attr::ASYNC_INVOCATION, trigger.is_async),
            KeyValue::new(attr::FUNCTION_ARN, lambda_cx.invoked_function_arn.clone()),
            KeyValue::new(attr::FUNCTION_VERSION, lambda_cx.env_config.version.clone()),
            KeyValue::new(attr::FUNCTION_NAME, function_name.to_lowercase()),
            KeyValue::new(attr::RESOURCE_NAMES, function_name.clone()),
            KeyValue::new(attr::DD_ORIGIN, "lambda"),
        ];
        if let Some(ref source) = trigger.event_source {
            attrs.push(KeyValue::new(
                attr::FUNCTION_TRIGGER_EVENT_SOURCE,
                source.clone(),
            ));
        }
        if let Some(ref arn) = trigger.event_source_arn {
            attrs.push(KeyValue::new(
                attr::FUNCTION_TRIGGER_EVENT_SOURCE_ARN,
                arn.clone(),
            ));
        }
        builder.attributes = Some(attrs);

        let span = tracer.build_with_context(builder, &effective_cx);
        let cx = effective_cx.with_span(span);

        Self { cx, request_id }
    }

    pub(crate) fn set_error(&self, err: &impl std::fmt::Display) {
        let err_msg = err.to_string();
        tracing::warn!(request_id = self.request_id, "handler returned error");
        let span = self.cx.span();
        span.set_status(Status::Error {
            description: err_msg.clone().into(),
        });
        span.set_attribute(KeyValue::new(attr::ERROR, true));
        span.set_attribute(KeyValue::new(attr::ERROR_MESSAGE, err_msg));
        // error.type is omitted: lambda_runtime boxes the error, erasing its type.
    }

    /// Ends the root span.
    pub(crate) fn finish(self) {
        self.cx.span().end();
    }
}

/// Owns the full lifecycle of a single Lambda invocation's tracing state.
///
/// Holds the root span and all inferred spans created from the trigger payload.
/// Call [`start`](Self::start) before the handler, then [`finish`](Self::finish) after.
pub(crate) struct Invocation {
    /// The `aws.lambda` root span for this invocation.
    lambda_span: LambdaSpan,
    /// Inferred spans derived from the trigger payload (e.g., SQS, SNS).
    /// May be empty when the payload has no recognisable trigger.
    inferred_spans: InferredSpanScope,
    /// Wall-clock time at invocation start, used to compute inferred span durations.
    started_at: SystemTime,
}

impl Invocation {
    pub(crate) fn start(
        tracer: &SdkTracer,
        inferrer: &SpanInferrer,
        payload: &str,
        lambda_cx: &lambda_runtime::Context,
        cold_start: bool,
    ) -> Self {
        let extraction = extract_trigger(inferrer, payload);
        let inferred_spans = InferredSpanScope::start(
            tracer,
            &extraction.upstream_cx,
            &extraction.inference_result,
        );
        let trigger = TriggerContext {
            parent_cx: inferred_spans.innermost_context(&extraction.upstream_cx),
            is_async: extraction.is_async,
            event_source: extraction.event_source,
            event_source_arn: extraction.event_source_arn,
        };
        let lambda_span = LambdaSpan::start(tracer, &trigger, lambda_cx, cold_start);

        Self {
            lambda_span,
            inferred_spans,
            started_at: SystemTime::now(),
        }
    }

    /// Returns the OTel context to use as the active context during handler execution.
    ///
    /// User handler spans should be children of the root span, so this context must
    /// be passed to [`FutureExt::with_context`](opentelemetry::trace::FutureExt::with_context)
    /// (or equivalent) when running the handler future.
    #[must_use]
    pub(crate) fn handler_context(&self) -> Context {
        self.lambda_span.cx.clone()
    }

    /// Records any handler error and ends all spans.
    ///
    /// The result is returned unchanged; this method only has side effects
    /// (error attributes, span end times).
    pub(crate) fn finish<R, Err>(self, result: Result<R, Err>) -> Result<R, Err>
    where
        Err: std::fmt::Display,
    {
        let invocation_end = SystemTime::now();

        if let Err(ref err) = result {
            self.lambda_span.set_error(err);
        }
        self.finish_spans(invocation_end);
        result
    }

    /// Ends all spans in the correct order: inferred spans first, then the root span.
    ///
    /// Inferred spans must be ended before the root span so that timing relationships
    /// are correct in the Datadog backend.
    fn finish_spans(self, invocation_end: SystemTime) {
        self.inferred_spans.end(self.started_at, invocation_end);
        self.lambda_span.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span_inferrer::TriggerContext;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceFlags, TraceId, TraceState, TracerProvider as _,
    };
    use opentelemetry::Value;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};

    fn test_provider() -> (SdkTracerProvider, InMemorySpanExporter) {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        (provider, exporter)
    }

    fn test_lambda_cx() -> lambda_runtime::Context {
        let mut cx = lambda_runtime::Context::default();
        cx.request_id = "req-123".to_string();
        cx.invoked_function_arn = "arn:aws:lambda:us-east-1:123:function:my-function".to_string();
        std::sync::Arc::make_mut(&mut cx.env_config).function_name = "My-Function".to_string();
        std::sync::Arc::make_mut(&mut cx.env_config).version = "$LATEST".to_string();
        cx
    }

    fn test_trigger() -> TriggerContext {
        TriggerContext {
            parent_cx: Context::current(),
            is_async: false,
            event_source: None,
            event_source_arn: None,
        }
    }

    fn find_attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a Value> {
        attrs
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| &kv.value)
    }

    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<SpanData> {
        exporter.get_finished_spans().unwrap()
    }

    #[test]
    fn sets_expected_attributes_on_root_span() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");

        let lambda_cx = test_lambda_cx();
        let trigger = TriggerContext {
            is_async: true,
            ..test_trigger()
        };

        let span = LambdaSpan::start(&tracer, &trigger, &lambda_cx, true);
        span.finish();
        provider.force_flush().unwrap();

        let spans = finished_spans(&exporter);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name.as_ref(), ROOT_SPAN_NAME);
        let attrs = &spans[0].attributes;

        assert_eq!(
            find_attr(attrs, "_dd.origin"),
            Some(&Value::String("lambda".into()))
        );
        assert_eq!(
            find_attr(attrs, "request_id"),
            Some(&Value::String("req-123".into()))
        );
        assert_eq!(
            find_attr(attrs, "resource.name"),
            Some(&Value::String("My-Function".into()))
        );
        assert_eq!(
            find_attr(attrs, "operation.name"),
            Some(&Value::String("aws.lambda".into()))
        );
        assert_eq!(
            find_attr(attrs, "functionname"),
            Some(&Value::String("my-function".into()))
        );
        assert_eq!(find_attr(attrs, "cold_start"), Some(&Value::Bool(true)));
        assert_eq!(
            find_attr(attrs, "async_invocation"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn inherits_parent_trace_id_for_root_span() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");

        let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let parent_sc = SpanContext::new(
            trace_id,
            SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            TraceFlags::SAMPLED,
            true,
            TraceState::default(),
        );
        let parent_cx = Context::current().with_remote_span_context(parent_sc);
        let trigger = TriggerContext {
            parent_cx,
            ..test_trigger()
        };

        let span = LambdaSpan::start(&tracer, &trigger, &test_lambda_cx(), false);
        assert_eq!(span.cx.span().span_context().trace_id(), trace_id);
    }

    #[tokio::test]
    async fn error_handler_sets_error_attributes() {
        let (provider, exporter) = test_provider();
        let invocation = Invocation {
            lambda_span: LambdaSpan::start(
                &provider.tracer("test"),
                &test_trigger(),
                &test_lambda_cx(),
                false,
            ),
            inferred_spans: InferredSpanScope::empty(),
            started_at: SystemTime::now(),
        };

        let _: Result<(), String> = invocation.finish(Err::<(), String>("boom".to_string()));
        provider.force_flush().unwrap();

        let spans = finished_spans(&exporter);
        let attrs = &spans[0].attributes;
        assert_eq!(find_attr(attrs, "error"), Some(&Value::Bool(true)));
        assert_eq!(
            find_attr(attrs, "error.message"),
            Some(&Value::String("boom".into()))
        );
    }

    #[tokio::test]
    async fn successful_handler_sets_no_error_attributes() {
        let (provider, exporter) = test_provider();
        let invocation = Invocation {
            lambda_span: LambdaSpan::start(
                &provider.tracer("test"),
                &test_trigger(),
                &test_lambda_cx(),
                false,
            ),
            inferred_spans: InferredSpanScope::empty(),
            started_at: SystemTime::now(),
        };

        let _: Result<(), String> = invocation.finish(Ok(()));
        provider.force_flush().unwrap();

        let spans = finished_spans(&exporter);
        let attrs = &spans[0].attributes;
        assert!(find_attr(attrs, "error").is_none());
        assert!(find_attr(attrs, "error.message").is_none());
    }

    #[test]
    fn start_invocation_materializes_inferred_spans_for_sqs_events() {
        let (provider, _) = test_provider();
        let payload = serde_json::json!({
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
                        "stringValue": serde_json::to_string(&serde_json::json!({
                            "x-datadog-trace-id": "12345",
                            "x-datadog-parent-id": "67890",
                            "x-datadog-sampling-priority": "1"
                        }))
                        .unwrap(),
                        "dataType": "String"
                    }
                }
            }]
        })
        .to_string();

        let inferrer = crate::span_inferrer::build_inferrer();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, TRACER_NAME);
        let invocation = Invocation::start(&tracer, &inferrer, &payload, &test_lambda_cx(), false);
        assert!(invocation
            .handler_context()
            .span()
            .span_context()
            .is_valid());
        assert!(!invocation.inferred_spans.is_empty());
    }
}
