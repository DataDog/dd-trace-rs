// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Panic and unwrap are banned in production code to prevent silent Lambda crashes.
// Tests are exempt so they can use `.unwrap()` freely.
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

mod attribute_keys;
mod invocation;

use datadog_opentelemetry::configuration::{Config, ConfigBuilder};
use invocation::{Invocation, TRACER_NAME};
use lambda_runtime::tower::Service;
use lambda_runtime::LambdaEvent;
use opentelemetry::trace::{FutureExt, TracerProvider};
use opentelemetry_sdk::trace::SdkTracer;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::task::{self, Poll};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// Error returned by [`TracedService`].
///
/// This remains compatible with [`lambda_runtime::run`] by converting into
/// [`lambda_runtime::Diagnostic`], while also providing a stable display string
/// for invocation span error reporting.
#[derive(Debug)]
pub struct TracedServiceError(lambda_runtime::Diagnostic);

impl fmt::Display for TracedServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.error_message)
    }
}

impl From<lambda_runtime::Diagnostic> for TracedServiceError {
    fn from(value: lambda_runtime::Diagnostic) -> Self {
        Self(value)
    }
}

impl From<TracedServiceError> for lambda_runtime::Diagnostic {
    fn from(value: TracedServiceError) -> Self {
        value.0
    }
}

impl From<lambda_runtime::Error> for TracedServiceError {
    fn from(value: lambda_runtime::Error) -> Self {
        Self(value.into())
    }
}

impl From<serde_json::Error> for TracedServiceError {
    fn from(value: serde_json::Error) -> Self {
        lambda_runtime::Error::from(value).into()
    }
}

/// A Lambda service wrapped with Datadog tracing.
///
/// Owns the [`SdkTracerProvider`] lifecycle,
/// applies Lambda-appropriate defaults, and implements [`Service`] so it composes
/// naturally with tower middleware.
///
/// # Examples
///
/// ```ignore
/// // Zero-config
/// lambda_runtime::run(TracedService::new(
///     lambda_runtime::service_fn(my_handler),
/// )).await
///
/// // Set service/env/version
/// let mut config = Config::builder();
/// config.set_service("my-service".into());
/// config.set_env("prod".into());
/// config.set_version("1.2.3".into());
///
/// lambda_runtime::run(TracedService::with_config(
///     lambda_runtime::service_fn(my_handler),
///     config,
/// )).await
///
/// // With tower middleware
/// lambda_runtime::run(
///     TracedService::new(
///         tower::ServiceBuilder::new()
///             .layer(some_middleware)
///             .service(lambda_runtime::service_fn(my_handler)),
///     )
/// ).await
/// ```
pub struct TracedService<S, E, R> {
    inner: S,
    tracer: SdkTracer,
    cold_start: bool,
    _phantom: PhantomData<fn(E) -> R>,
}

impl<S, E, R> TracedService<S, E, R> {
    /// Wraps a Tower service with Datadog tracing using the default Datadog config sources.
    ///
    /// This is equivalent to calling [`with_config`](Self::with_config) with
    /// [`Config::builder()`], then forcing the Lambda-safe tracing defaults.
    pub fn new(inner: S) -> Self
    where
        S: Service<LambdaEvent<E>, Response = R>,
    {
        Self::with_config(inner, Config::builder())
    }

    /// Wraps a Tower service with Datadog tracing using a caller-provided config builder.
    ///
    /// Use this constructor when you want to apply Tower middleware after tracing
    /// has started but before your Lambda service executes.
    ///
    /// The provided Datadog config builder is always forced to Lambda-safe defaults:
    /// - `trace_stats_computation_enabled = false`
    /// - `trace_writer_synchronous_write = true`
    pub fn with_config(inner: S, config: ConfigBuilder) -> Self
    where
        S: Service<LambdaEvent<E>, Response = R>,
    {
        let provider = {
            let mut config = config;
            // Stats are computed server-side by the extension; client-side computation is
            // redundant.
            config.set_trace_stats_computation_enabled(false);
            // Synchronous writes make the Datadog exporter wait for the completed trace chunk
            // to flush when the root span ends, which helps reduce span loss when the Lambda
            // process freezes after the handler returns.
            config.set_trace_writer_synchronous_write(true);
            datadog_opentelemetry::tracing()
                .with_config(config.build())
                .init()
        };
        let tracer = TracerProvider::tracer(&provider, TRACER_NAME);
        Self {
            inner,
            tracer,
            cold_start: true,
            _phantom: PhantomData,
        }
    }

    fn take_cold_start(&mut self) -> bool {
        std::mem::replace(&mut self.cold_start, false)
    }
}

impl<S, E, R> Service<LambdaEvent<Box<RawValue>>> for TracedService<S, E, R>
where
    S: Service<LambdaEvent<E>, Response = R>,
    S::Future: Future<Output = Result<R, S::Error>> + Send + 'static,
    S::Error: Into<lambda_runtime::Diagnostic> + fmt::Debug,
    E: DeserializeOwned + Send + 'static,
    R: Send + 'static,
{
    type Response = R;
    type Error = TracedServiceError;
    type Future = BoxFuture<Result<R, TracedServiceError>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|err| TracedServiceError::from(err.into()))
    }

    fn call(&mut self, event: LambdaEvent<Box<RawValue>>) -> Self::Future {
        let cold_start = self.take_cold_start();
        let invocation = Invocation::start(&self.tracer, &event.context, cold_start);
        let typed_payload = match serde_json::from_str::<E>(event.payload.get()) {
            Ok(payload) => payload,
            Err(err) => {
                return Box::pin(async move {
                    let result: Result<R, TracedServiceError> = Err(err.into());
                    invocation.finish(result)
                });
            }
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = {
            let _guard = invocation.handler_context().attach();
            self.inner.call(typed_event).with_current_context()
        };
        Box::pin(async move {
            let result = fut.await;
            invocation.finish(result.map_err(|err| TracedServiceError::from(err.into())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt;
    use opentelemetry::Context;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    fn noop_handler(
        _: LambdaEvent<serde_json::Value>,
    ) -> std::future::Ready<Result<(), lambda_runtime::Error>> {
        std::future::ready(Ok(()))
    }

    #[allow(clippy::type_complexity)]
    fn test_handler() -> TracedService<ReadyService, serde_json::Value, ()> {
        let provider = SdkTracerProvider::builder().build();
        let tracer = TracerProvider::tracer(&provider, TRACER_NAME);
        TracedService {
            inner: ReadyService,
            tracer,
            cold_start: true,
            _phantom: PhantomData,
        }
    }

    struct ReadyService;

    impl Service<LambdaEvent<serde_json::Value>> for ReadyService {
        type Response = ();
        type Error = lambda_runtime::Error;
        type Future = std::future::Ready<Result<(), lambda_runtime::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, event: LambdaEvent<serde_json::Value>) -> Self::Future {
            noop_handler(event)
        }
    }

    struct ReadyCountingService {
        ready_calls: Arc<AtomicUsize>,
    }

    struct ContextRecordingService {
        saw_active_span_in_call: Arc<AtomicBool>,
    }

    struct StringErrorReadyService;

    impl Service<LambdaEvent<serde_json::Value>> for ReadyCountingService {
        type Response = ();
        type Error = lambda_runtime::Error;
        type Future = std::future::Ready<Result<(), lambda_runtime::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.ready_calls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: LambdaEvent<serde_json::Value>) -> Self::Future {
            std::future::ready(Ok(()))
        }
    }

    impl Service<LambdaEvent<serde_json::Value>> for StringErrorReadyService {
        type Response = ();
        type Error = String;
        type Future = std::future::Ready<Result<(), String>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: LambdaEvent<serde_json::Value>) -> Self::Future {
            std::future::ready(Ok(()))
        }
    }

    impl Service<LambdaEvent<serde_json::Value>> for ContextRecordingService {
        type Response = ();
        type Error = lambda_runtime::Error;
        type Future = std::future::Ready<Result<(), lambda_runtime::Error>>;

        fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: LambdaEvent<serde_json::Value>) -> Self::Future {
            self.saw_active_span_in_call
                .store(Context::current().has_active_span(), Ordering::Relaxed);
            std::future::ready(Ok(()))
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

    #[test]
    fn poll_ready_delegates_to_inner_service() {
        let ready_calls = Arc::new(AtomicUsize::new(0));
        let mut wrapped = TracedService::new(ReadyCountingService {
            ready_calls: Arc::clone(&ready_calls),
        });
        let waker = std::task::Waker::noop();
        let mut cx = task::Context::from_waker(waker);

        assert!(wrapped.poll_ready(&mut cx).is_ready());
        assert_eq!(ready_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn supports_non_lambda_runtime_error_types() {
        let _wrapped = TracedService::new(StringErrorReadyService);
    }

    #[tokio::test]
    async fn call_runs_sync_phase_under_invocation_context() {
        let saw_active_span_in_call = Arc::new(AtomicBool::new(false));
        let mut wrapped = TracedService::new(ContextRecordingService {
            saw_active_span_in_call: Arc::clone(&saw_active_span_in_call),
        });

        let payload = RawValue::from_string("null".to_string()).unwrap();
        let event = LambdaEvent::new(payload, lambda_runtime::Context::default());
        wrapped.call(event).await.unwrap();

        assert!(saw_active_span_in_call.load(Ordering::Relaxed));
    }
}
