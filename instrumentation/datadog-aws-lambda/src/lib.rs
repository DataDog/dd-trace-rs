// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Panic and unwrap are banned in production code to prevent silent Lambda crashes.
// Tests are exempt so they can use `.unwrap()` freely.
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

mod attribute_keys;
mod invocation;

use invocation::{Invocation, TRACER_NAME};
use lambda_runtime::tower::Service;
use lambda_runtime::LambdaEvent;
use opentelemetry::trace::FutureExt;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use std::marker::PhantomData;
use std::task::{self, Poll};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// Applies Lambda-appropriate tracing defaults to a [`ConfigBuilder`].
///
/// These settings are enforced for correctness in Lambda:
/// - `trace_stats_computation_enabled = false` (the extension handles stats)
/// - `trace_writer_synchronous_write = true` (flush blocks until spans reach agent)
fn apply_lambda_tracing_defaults(
    mut builder: datadog_opentelemetry::configuration::ConfigBuilder,
) -> datadog_opentelemetry::configuration::ConfigBuilder {
    builder.set_trace_stats_computation_enabled(false);
    builder.set_trace_writer_synchronous_write(true);
    builder
}

/// A Lambda handler wrapped with Datadog tracing.
///
/// Owns the [`SdkTracerProvider`](opentelemetry_sdk::trace::SdkTracerProvider) lifecycle,
/// applies Lambda-appropriate defaults, and implements [`tower::Service`] so it composes
/// naturally with tower middleware.
///
/// The inner handler is any [`tower::Service`] that accepts `LambdaEvent<E>`. Plain async
/// functions can be converted with [`service_fn`](lambda_runtime::service_fn).
///
/// # Examples
///
/// ```ignore
/// use lambda_runtime::service_fn;
///
/// // Zero-config (Lambda defaults applied automatically)
/// let config = datadog_opentelemetry::configuration::Config::builder();
/// lambda_runtime::run(WrappedHandler::new(service_fn(my_handler), config)).await
///
/// // Custom config
/// let mut builder = datadog_opentelemetry::configuration::Config::builder();
/// builder.set_service("my-svc".into());
/// builder.set_env("prod".into());
/// lambda_runtime::run(WrappedHandler::new(service_fn(my_handler), builder)).await
///
/// // With tower middleware between tracing and the handler
/// let svc = tower::ServiceBuilder::new()
///     .layer(some_middleware)
///     .service(service_fn(my_handler));
/// lambda_runtime::run(WrappedHandler::new(svc, datadog_opentelemetry::configuration::Config::builder())).await
/// ```
pub struct WrappedHandler<S, E, R> {
    inner: S,
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
    tracer: opentelemetry_sdk::trace::SdkTracer,
    cold_start: bool,
    _phantom: PhantomData<fn(E) -> R>,
}

impl<S, E, R> WrappedHandler<S, E, R> {
    pub fn new(
        handler: S,
        config: datadog_opentelemetry::configuration::ConfigBuilder,
    ) -> Self {
        let config = apply_lambda_tracing_defaults(config);
        let provider = datadog_opentelemetry::tracing().with_config(config.build()).init();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, TRACER_NAME);
        Self {
            inner: handler,
            provider,
            tracer,
            cold_start: true,
            _phantom: PhantomData,
        }
    }

    fn take_cold_start(&mut self) -> bool {
        std::mem::replace(&mut self.cold_start, false)
    }
}

impl<S, E, R> Service<LambdaEvent<Box<RawValue>>> for WrappedHandler<S, E, R>
where
    S: Service<LambdaEvent<E>, Response = R, Error = lambda_runtime::Error>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    E: DeserializeOwned + Send + 'static,
    R: Send + 'static,
{
    type Response = R;
    type Error = lambda_runtime::Error;
    type Future = BoxFuture<Result<R, lambda_runtime::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, event: LambdaEvent<Box<RawValue>>) -> Self::Future {
        let cold_start = self.take_cold_start();
        let mut inner = self.inner.clone();
        let provider = self.provider.clone();
        let invocation = Invocation::start(&self.tracer, &event.context, cold_start);
        // Deserialize here rather than letting the runtime do it so that
        // deserialization errors are captured on the span. If we took
        // LambdaEvent<E> directly, the runtime would handle the error
        // before our code runs and the invocation would not be traced.
        let typed_payload = match serde_json::from_str::<E>(event.payload.get()) {
            Ok(payload) => payload,
            Err(err) => {
                return Box::pin(async move {
                    let result: Result<R, lambda_runtime::Error> = Err(err.into());
                    let result = invocation.finish(result);
                    if let Err(err) = provider.force_flush() {
                        tracing::error!("flush failed: {err}");
                    }
                    result
                });
            }
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = inner.call(typed_event);
        Box::pin(async move {
            let result = fut.with_context(invocation.handler_context()).await;
            let result = invocation.finish(result);
            if let Err(err) = provider.force_flush() {
                tracing::error!("flush failed: {err}");
            }
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lambda_runtime::service_fn;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type NoopService = lambda_runtime::tower::util::ServiceFn<
        fn(LambdaEvent<serde_json::Value>) -> std::future::Ready<Result<(), lambda_runtime::Error>>,
    >;

    fn noop_handler(
        _: LambdaEvent<serde_json::Value>,
    ) -> std::future::Ready<Result<(), lambda_runtime::Error>> {
        std::future::ready(Ok(()))
    }

    fn test_handler() -> WrappedHandler<NoopService, serde_json::Value, ()> {
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, TRACER_NAME);
        WrappedHandler {
            inner: service_fn(noop_handler as fn(_) -> _),
            provider,
            tracer,
            cold_start: true,
            _phantom: PhantomData,
        }
    }

    #[test]
    fn cold_start_is_tracked_per_handler() {
        let mut first = test_handler();
        assert!(first.take_cold_start());
        assert!(!first.take_cold_start());

        let mut second = test_handler();
        assert!(second.take_cold_start());
        assert!(!second.take_cold_start());
    }

    /// Sends a JSON payload through WrappedHandler and verifies the inner handler receives
    /// the deserialized payload and its response is returned unchanged.
    #[tokio::test]
    async fn handler_receives_payload_and_returns_response() {
        // Handler that echoes the payload back as the response.
        async fn echo(
            event: LambdaEvent<serde_json::Value>,
        ) -> Result<serde_json::Value, lambda_runtime::Error> {
            Ok(event.payload)
        }

        let input = r#"{"key":"value"}"#;
        let raw = RawValue::from_string(input.to_string()).unwrap();
        let event = LambdaEvent::new(raw, lambda_runtime::Context::default());

        let mut handler = WrappedHandler::new(
            service_fn(echo),
            datadog_opentelemetry::configuration::Config::builder(),
        );
        let response = handler.call(event).await.unwrap();

        assert_eq!(response, serde_json::json!({"key": "value"}));
    }

    /// Composes a middleware layer between tracing and the handler, then verifies
    /// both the middleware and handler execute.
    ///
    /// ```text
    /// WrappedHandler (tracing) -> counter middleware -> echo handler
    /// ```
    #[tokio::test]
    async fn middleware_between_tracing_and_handler_executes() {
        // Handler that echoes the payload back as the response.
        async fn echo(
            event: LambdaEvent<serde_json::Value>,
        ) -> Result<serde_json::Value, lambda_runtime::Error> {
            Ok(event.payload)
        }

        // Counter that the middleware increments to prove it ran.
        let middleware_call_count = Arc::new(AtomicUsize::new(0));
        let counter = middleware_call_count.clone();

        // Compose: counter middleware -> echo handler.
        let service_with_middleware = lambda_runtime::tower::ServiceBuilder::new()
            .map_request(move |req: LambdaEvent<serde_json::Value>| {
                counter.fetch_add(1, Ordering::SeqCst);
                req
            })
            .service(service_fn(echo));

        let input = r#"{"hello":"world"}"#;
        let raw = RawValue::from_string(input.to_string()).unwrap();
        let event = LambdaEvent::new(raw, lambda_runtime::Context::default());

        let mut handler = WrappedHandler::new(
            service_with_middleware,
            datadog_opentelemetry::configuration::Config::builder(),
        );
        let response = handler.call(event).await.unwrap();

        assert_eq!(
            middleware_call_count.load(Ordering::SeqCst),
            1,
            "middleware should have run"
        );
        assert_eq!(
            response,
            serde_json::json!({"hello": "world"}),
            "handler should have echoed payload"
        );
    }
}
