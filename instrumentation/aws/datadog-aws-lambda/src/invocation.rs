// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::attribute_keys as attr;
use crate::span_inferrer::{InferredSpanScope, TriggerContext, TriggerExtractor};

use lambda_runtime::LambdaEvent;
use opentelemetry::trace::{SpanKind, TraceContextExt, Tracer, TracerProvider as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use serde_json::Value;
use std::time::SystemTime;

static TRACER_NAME: &str = "datadog-lambda-rs";

/// The Lambda invocation (aws.lambda) root span.
pub(crate) struct LambdaSpan {
    cx: Context,
    request_id: String,
}

impl LambdaSpan {
    pub(crate) fn start(
        tracer: &SdkTracer,
        trigger: &TriggerContext,
        lambda_cx: &lambda_runtime::Context,
        cold_start: bool,
    ) -> Self {
        let function_name = &lambda_cx.env_config.function_name;
        let request_id = lambda_cx.request_id.clone();

        tracing::debug!(request_id, "creating invocation root span");

        // Use the extracted trace context as the parent if it's present
        let effective_cx = if trigger.parent_cx.span().span_context().is_valid() {
            trigger.parent_cx.clone()
        } else {
            Context::current()
        };

        let mut builder = tracer.span_builder(TRACER_NAME);
        builder.span_kind = Some(SpanKind::Server);
        let mut attrs = vec![
            KeyValue::new(attr::OPERATION_NAME, "aws.lambda"),
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
        if let Some(source) = trigger.event_source {
            attrs.push(KeyValue::new(attr::FUNCTION_TRIGGER_EVENT_SOURCE, source));
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
        let err_msg = format!("{err}");
        tracing::warn!(request_id = self.request_id, "handler returned error");
        let span = self.cx.span();
        span.set_status(opentelemetry::trace::Status::Error {
            description: err_msg.clone().into(),
        });
        span.set_attribute(KeyValue::new(attr::ERROR, true));
        span.set_attribute(KeyValue::new(attr::ERROR_MESSAGE, err_msg));
        // error.type is omitted as an attribute as lambda_runtime boxes the error (erasing its
        // type). Is there a way to still includde this information?
    }

    pub(crate) fn finish(self) {
        self.cx.span().end();
    }
}

pub(crate) struct Invocation {
    lambda_span: LambdaSpan,
    inferred_spans: InferredSpanScope,
    started_at: SystemTime,
}

impl Invocation {
    pub(crate) fn start(
        event: &LambdaEvent<Value>,
        provider: &SdkTracerProvider,
        cold_start: bool,
    ) -> Self {
        let tracer = provider.tracer(TRACER_NAME);
        let extraction = TriggerExtractor::extract(&event.payload);
        let (parent_cx, inferred_spans) = InferredSpanScope::start(
            &tracer,
            &extraction.upstream_cx,
            extraction.inferred_span.as_ref(),
        );
        let trigger = TriggerContext {
            parent_cx,
            is_async: extraction.is_async,
            event_source: extraction.event_source,
            event_source_arn: extraction.event_source_arn,
        };
        let lambda_span = LambdaSpan::start(&tracer, &trigger, &event.context, cold_start);

        Self {
            lambda_span,
            inferred_spans,
            started_at: SystemTime::now(),
        }
    }

    pub(crate) fn handler_context(&self) -> Context {
        self.lambda_span.cx.clone()
    }

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

    fn finish_spans(self, invocation_end: SystemTime) {
        self.inferred_spans.end(self.started_at, invocation_end);
        self.lambda_span.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span_inferrer::TriggerContext;
    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId, TraceState};
    use opentelemetry::Value;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SpanData};

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
    fn extracts_headers_from_raw_invocation_event() {
        // Even when a user's handler type <E> does not include headers, we still need to see
        // the full raw JSON in order to extract potential trace context from event.headers.
        let (provider, _) = test_provider();

        let raw_event = LambdaEvent::new(
            serde_json::json!({
                "body": "hello",
                "headers": {
                    "x-datadog-trace-id": "99999",
                    "x-datadog-parent-id": "11111",
                    "x-datadog-sampling-priority": "1"
                }
            }),
            lambda_runtime::Context::default(),
        );

        let invocation = Invocation::start(&raw_event, &provider, false);
        assert!(invocation
            .handler_context()
            .span()
            .span_context()
            .is_valid());
    }

    #[test]
    fn start_invocation_materializes_inferred_spans_for_sqs_events() {
        let (provider, _) = test_provider();
        let raw_event = LambdaEvent::new(
            serde_json::json!({
                "Records": [{
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789:test-queue",
                    "awsRegion": "us-east-1",
                    "body": "hello",
                    "attributes": { "SentTimestamp": "1718444400000" },
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
            }),
            test_lambda_cx(),
        );

        let invocation = Invocation::start(&raw_event, &provider, false);
        assert!(invocation
            .handler_context()
            .span()
            .span_context()
            .is_valid());
        assert!(!invocation.inferred_spans.is_empty());
    }
}
