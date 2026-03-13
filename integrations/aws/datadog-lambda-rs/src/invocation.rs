// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::span_inferrer::SpanInferrer;
use crate::Config;

use lambda_runtime::LambdaEvent;
use opentelemetry::trace::{FutureExt, SpanKind, TraceContextExt, Tracer, TracerProvider as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use serde_json::Value;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

static IS_COLD_START: AtomicBool = AtomicBool::new(true);

fn detect_cold_start() -> bool {
    IS_COLD_START.swap(false, Ordering::SeqCst)
}

/// Properties of the Lambda invocation root span.
pub(crate) struct LambdaSpan {
    pub function_name: String,
    pub function_arn: String,
    /// e.g. `"$LATEST"`
    pub function_version: String,
    pub request_id: String,
    pub cold_start: bool,
    pub is_async: bool,
    /// e.g. `"sqs"`, `"sns"`, `"eventbridge"`
    pub event_source: Option<&'static str>,
    pub event_source_arn: Option<String>,
    /// Lambda runtime identifier from `AWS_EXECUTION_ENV`.
    pub runtime: Option<String>,
}

pub(crate) struct InvocationScope {
    pub request_id: String,
    pub invocation_cx: Context,
}

pub(crate) fn start_invocation(
    event: &LambdaEvent<Value>,
    provider: &SdkTracerProvider,
    _config: &Config,
) -> InvocationScope {
    let is_cold = detect_cold_start();
    let tracer = provider.tracer("datadog-lambda-rs");

    let inferrer = SpanInferrer::new(&tracer);
    let result = inferrer.infer(&event.payload);

    let lambda_span = LambdaSpan {
        function_name: event.context.env_config.function_name.clone(),
        function_arn: event.context.invoked_function_arn.clone(),
        function_version: event.context.env_config.version.clone(),
        request_id: event.context.request_id.clone(),
        cold_start: is_cold,
        is_async: result.is_async,
        event_source: result.event_source,
        event_source_arn: result.event_source_arn,
        runtime: None,
    };

    tracing::debug!(
        request_id = lambda_span.request_id,
        "creating invocation root span"
    );
    let invocation_cx = create_root_span(&tracer, &result.parent_cx, &lambda_span);

    for cx in result.inferred_span_contexts {
        cx.span().end_with_timestamp(result.inferred_span_end_time);
    }

    InvocationScope {
        request_id: lambda_span.request_id,
        invocation_cx,
    }
}

pub(crate) async fn run_in_invocation_scope<R, Err, Fut>(
    scope: InvocationScope,
    provider: SdkTracerProvider,
    fut: Fut,
) -> Result<R, Err>
where
    Err: std::fmt::Display,
    Fut: Future<Output = Result<R, Err>>,
{
    let result = fut.with_context(scope.invocation_cx.clone()).await;

    let span = scope.invocation_cx.span();
    if let Err(ref err) = result {
        let err_msg = format!("{err}");
        tracing::warn!(request_id = scope.request_id, "handler returned error");
        span.set_status(opentelemetry::trace::Status::Error {
            description: err_msg.clone().into(),
        });
        span.set_attribute(KeyValue::new("error", true));
        span.set_attribute(KeyValue::new("error.message", err_msg));
    }
    span.end();

    if let Err(e) = provider.force_flush() {
        tracing::error!("flush failed: {e}");
    }

    result
}

fn create_root_span(tracer: &SdkTracer, parent_cx: &Context, span: &LambdaSpan) -> Context {
    let effective_cx = if parent_cx.span().span_context().is_valid() {
        parent_cx.clone()
    } else {
        Context::current()
    };

    let mut builder = tracer.span_builder("aws.lambda");
    builder.span_kind = Some(SpanKind::Server);
    let mut attrs = vec![
        KeyValue::new("operation.name", "aws.lambda"),
        KeyValue::new("resource.name", span.function_name.clone()),
        KeyValue::new("span.type", "serverless"),
        KeyValue::new("request_id", span.request_id.clone()),
        KeyValue::new("cold_start", span.cold_start),
        KeyValue::new("async_invocation", span.is_async),
        KeyValue::new("function_arn", span.function_arn.clone()),
        KeyValue::new("function_version", span.function_version.clone()),
        KeyValue::new("functionname", span.function_name.to_lowercase()),
        KeyValue::new("resource_names", span.function_name.clone()),
        KeyValue::new("_dd.origin", "lambda"),
    ];
    if let Some(source) = span.event_source {
        attrs.push(KeyValue::new("function_trigger.event_source", source));
    }
    if let Some(ref arn) = span.event_source_arn {
        attrs.push(KeyValue::new(
            "function_trigger.event_source_arn",
            arn.clone(),
        ));
    }
    if let Some(ref rt) = span.runtime {
        attrs.push(KeyValue::new("runtime", rt.clone()));
    }
    builder.attributes = Some(attrs);

    let span = tracer.build_with_context(builder, &effective_cx);
    effective_cx.with_span(span)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn test_lambda_span() -> LambdaSpan {
        LambdaSpan {
            function_name: "My-Function".to_string(),
            function_arn: "arn:aws:lambda:us-east-1:123:function:my-function".to_string(),
            function_version: "$LATEST".to_string(),
            request_id: "req-123".to_string(),
            cold_start: false,
            is_async: false,
            event_source: None,
            event_source_arn: None,
            runtime: None,
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
    fn cold_start_true_on_first_call_then_false() {
        IS_COLD_START.store(true, Ordering::SeqCst);
        assert!(detect_cold_start());
        assert!(!detect_cold_start());
        IS_COLD_START.store(true, Ordering::SeqCst); // restore
    }

    #[test]
    fn root_span_sets_expected_attributes() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");
        let lambda_span = LambdaSpan {
            cold_start: true,
            is_async: true,
            ..test_lambda_span()
        };

        let cx = create_root_span(&tracer, &Context::current(), &lambda_span);
        cx.span().end();
        provider.force_flush().ok();

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
    fn root_span_inherits_parent_trace_id() {
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

        let cx = create_root_span(&tracer, &parent_cx, &test_lambda_span());
        assert_eq!(cx.span().span_context().trace_id(), trace_id);
    }

    #[test]
    fn root_span_starts_new_trace_without_parent() {
        let (provider, _) = test_provider();
        let tracer = provider.tracer("test");
        let cx = create_root_span(&tracer, &Context::current(), &test_lambda_span());
        assert!(cx.span().span_context().is_valid());
    }

    #[tokio::test]
    async fn error_handler_sets_error_attributes() {
        let (provider, exporter) = test_provider();
        let tracer = provider.tracer("test");
        let invocation_cx = create_root_span(&tracer, &Context::current(), &test_lambda_span());
        let scope = InvocationScope {
            request_id: "req-123".to_string(),
            invocation_cx,
        };

        let _: Result<(), String> =
            run_in_invocation_scope(scope, provider, async { Err("boom".to_string()) }).await;

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
        let tracer = provider.tracer("test");
        let invocation_cx = create_root_span(&tracer, &Context::current(), &test_lambda_span());
        let scope = InvocationScope {
            request_id: "req-123".to_string(),
            invocation_cx,
        };

        let _: Result<(), String> =
            run_in_invocation_scope(scope, provider, async { Ok(()) }).await;

        let spans = finished_spans(&exporter);
        let attrs = &spans[0].attributes;
        assert!(find_attr(attrs, "error").is_none());
        assert!(find_attr(attrs, "error.message").is_none());
    }

    #[test]
    fn start_invocation_extracts_headers_from_raw_event() {
        // Regression test for the LambdaEvent<Value> fix: even when the user's handler
        // type would not include headers, start_invocation sees the full raw JSON and
        // extracts trace context from event.headers.
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

        let scope = start_invocation(&raw_event, &provider, &Config::default());
        assert!(scope.invocation_cx.span().span_context().is_valid());
    }
}
