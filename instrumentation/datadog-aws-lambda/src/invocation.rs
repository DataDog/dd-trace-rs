// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Lifecycle management for a single Lambda invocation.
//!
//! Each invocation produces one *root span* (`aws.lambda`) that wraps the handler call.
//!
//! Typical usage:
//! 1. [`Invocation::start`] — create the root span before the handler runs.
//! 2. [`Invocation::handler_context`] — pass the returned context to the handler so its OTel spans
//!    are correctly parented.
//! 3. [`Invocation::finish`] — record errors and end the span after the handler returns.

use crate::attribute_keys as attr;

use opentelemetry::trace::{SpanKind, Status, TraceContextExt, Tracer};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::SdkTracer;

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
    /// The span is parented to the ambient OTel context, which is typically a new root trace.
    pub(crate) fn start(
        tracer: &SdkTracer,
        lambda_cx: &lambda_runtime::Context,
        cold_start: bool,
    ) -> Self {
        let function_name = &lambda_cx.env_config.function_name;
        let request_id = lambda_cx.request_id.clone();

        tracing::debug!(request_id, "creating invocation root span");

        let parent_cx = Context::current();

        let mut builder = tracer.span_builder(ROOT_SPAN_NAME);
        builder.span_kind = Some(SpanKind::Server);
        let attrs = vec![
            KeyValue::new(attr::OPERATION_NAME, ROOT_SPAN_NAME),
            KeyValue::new(attr::LANGUAGE, "rust"),
            KeyValue::new(attr::RESOURCE_NAME, function_name.clone()),
            KeyValue::new(attr::SPAN_TYPE, "serverless"),
            KeyValue::new(attr::REQUEST_ID, request_id.clone()),
            KeyValue::new(attr::COLD_START, cold_start),
            KeyValue::new(attr::FUNCTION_ARN, lambda_cx.invoked_function_arn.clone()),
            KeyValue::new(attr::FUNCTION_VERSION, lambda_cx.env_config.version.clone()),
            KeyValue::new(attr::FUNCTION_NAME, function_name.to_lowercase()),
            KeyValue::new(attr::RESOURCE_NAMES, function_name.clone()),
            KeyValue::new(attr::DD_ORIGIN, "lambda"),
        ];
        builder.attributes = Some(attrs);

        let span = tracer.build_with_context(builder, &parent_cx);
        let cx = parent_cx.with_span(span);

        Self { cx, request_id }
    }

    pub(crate) fn set_error(&self, err: &impl std::fmt::Display) {
        let err_msg = err.to_string();
        tracing::warn!(request_id = self.request_id, "handler returned error");
        let span = self.cx.span();
        span.set_status(Status::Error {
            description: err_msg.clone().into(),
        });
        span.set_attributes([
            KeyValue::new(attr::ERROR, true),
            KeyValue::new(attr::ERROR_MESSAGE, err_msg),
        ]);
        // error.type is omitted: lambda_runtime boxes the error, erasing its type.
    }

    /// Ends the root span.
    pub(crate) fn finish(self) {
        self.cx.span().end();
    }
}

/// Owns the full lifecycle of a single Lambda invocation's tracing state.
///
/// Holds the root span created for the handler call.
/// Call [`start`](Self::start) before the handler, then [`finish`](Self::finish) after.
pub(crate) struct Invocation {
    /// The `aws.lambda` root span for this invocation.
    lambda_span: LambdaSpan,
}

impl Invocation {
    pub(crate) fn start(
        tracer: &SdkTracer,
        lambda_cx: &lambda_runtime::Context,
        cold_start: bool,
    ) -> Self {
        let lambda_span = LambdaSpan::start(tracer, lambda_cx, cold_start);
        Self { lambda_span }
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

    /// Records any handler error and ends the root span.
    ///
    /// The result is returned unchanged; this method only has side effects
    /// (error attributes, span end times).
    pub(crate) fn finish<R, Err>(self, result: Result<R, Err>) -> Result<R, Err>
    where
        Err: std::fmt::Display,
    {
        if let Err(ref err) = result {
            self.lambda_span.set_error(err);
        }
        self.lambda_span.finish();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let span = LambdaSpan::start(&tracer, &lambda_cx, true);
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
        let _guard = Context::current()
            .with_remote_span_context(parent_sc)
            .attach();

        let span = LambdaSpan::start(&tracer, &test_lambda_cx(), false);
        assert_eq!(span.cx.span().span_context().trace_id(), trace_id);
    }

    #[tokio::test]
    async fn error_handler_sets_error_attributes() {
        let (provider, exporter) = test_provider();
        let invocation = Invocation {
            lambda_span: LambdaSpan::start(&provider.tracer("test"), &test_lambda_cx(), false),
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
            lambda_span: LambdaSpan::start(&provider.tracer("test"), &test_lambda_cx(), false),
        };

        let _: Result<(), String> = invocation.finish(Ok(()));
        provider.force_flush().unwrap();

        let spans = finished_spans(&exporter);
        let attrs = &spans[0].attributes;
        assert!(find_attr(attrs, "error").is_none());
        assert!(find_attr(attrs, "error.message").is_none());
    }
}
