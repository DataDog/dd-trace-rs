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
use std::future::Future;
use std::marker::PhantomData;
use std::task::{self, Poll};

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

#[derive(Default)]
pub struct Config {
    /// Service name. Overrides `DD_SERVICE`. Ignored when [`tracing`](Self::tracing) is `Some`.
    pub service: Option<String>,
    /// Deployment environment. Overrides `DD_ENV`. Ignored when [`tracing`](Self::tracing) is
    /// `Some`.
    pub env: Option<String>,
    /// Service version. Overrides `DD_VERSION`. Ignored when [`tracing`](Self::tracing) is `Some`.
    pub version: Option<String>,
    /// Full control over the OTel SDK and Datadog tracer config.
    ///
    /// When `None` (default), Lambda-appropriate defaults are applied and
    /// `service`/`env`/`version` above are forwarded. When `Some`, the builder is used as-is;
    /// `service`/`env`/`version` are ignored and you are responsible for setting:
    /// - `trace_stats_computation_enabled = false` (the Datadog agent handles stats for serverless
    ///   environments)
    /// - `trace_writer_synchronous_write = true` (so `force_flush()` blocks until spans reach
    ///   agent)
    pub tracing: Option<datadog_opentelemetry::DatadogTracingBuilder>,
}

fn build_tracing(
    service: Option<String>,
    env: Option<String>,
    version: Option<String>,
) -> datadog_opentelemetry::DatadogTracingBuilder {
    let mut builder = datadog_opentelemetry::configuration::Config::builder();
    // Stats are computed server-side by the extension; client-side computation is redundant.
    builder.set_trace_stats_computation_enabled(false);
    // Synchronous writes make force_flush() block until data reaches the agent,
    // this helps reduce span loss when the Lambda process freezes after the handler returns.
    builder.set_trace_writer_synchronous_write(true);
    if let Some(s) = service {
        builder.set_service(s);
    }
    if let Some(e) = env {
        builder.set_env(e);
    }
    if let Some(v) = version {
        builder.set_version(v);
    }
    datadog_opentelemetry::tracing().with_config(builder.build())
}

/// A Lambda handler wrapped with Datadog tracing.
///
/// Owns the [`SdkTracerProvider`](opentelemetry_sdk::trace::SdkTracerProvider) lifecycle,
/// applies Lambda-appropriate defaults, and implements [`tower::Service`] so it composes
/// naturally with tower middleware.
///
/// # Examples
///
/// ```ignore
/// // Zero-config
/// lambda_runtime::run(WrappedHandler::new(
///     lambda_runtime::service_fn(my_handler),
///     Config::default(),
/// )).await
///
/// // Set service/env/version
/// lambda_runtime::run(WrappedHandler::new(
///     lambda_runtime::service_fn(my_handler),
///     Config {
///         service: Some("my-service".into()),
///         env: Some("prod".into()),
///         ..Default::default()
///     },
/// )).await
///
/// // Full tracer control
/// lambda_runtime::run(WrappedHandler::new(
///     lambda_runtime::service_fn(my_handler),
///     Config {
///         tracing: Some(
///             datadog_opentelemetry::tracing()
///                 .with_config(builder_config_here)
///                 .with_span_processor(MyProcessor),
///         ),
///         ..Default::default()
///     },
/// )).await
///
/// // With tower middleware
/// lambda_runtime::run(
///     WrappedHandler::new(
///         tower::ServiceBuilder::new()
///             .layer(some_middleware)
///             .service(lambda_runtime::service_fn(my_handler)),
///         Config::default(),
///     )
/// ).await
/// ```
pub struct WrappedHandler<S, E, R> {
    inner: S,
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
    tracer: opentelemetry_sdk::trace::SdkTracer,
    cold_start: bool,
    _phantom: PhantomData<fn(E) -> R>,
}

impl<S, E, R> WrappedHandler<S, E, R> {
    /// Wraps a Tower service with Datadog tracing.
    ///
    /// Use this constructor when you want to apply Tower middleware after tracing
    /// has started but before your Lambda handler executes.
    pub fn new(inner: S, config: Config) -> Self
    where
        S: Service<LambdaEvent<E>, Response = R>,
    {
        let Config {
            tracing,
            service: service_name,
            env,
            version,
        } = config;
        let provider = tracing
            .unwrap_or_else(|| build_tracing(service_name, env, version))
            .init();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, TRACER_NAME);
        Self {
            inner,
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
    S: Service<LambdaEvent<E>, Response = R>,
    S::Future: Future<Output = Result<R, S::Error>> + Send + 'static,
    S::Error: Into<lambda_runtime::Error>,
    E: DeserializeOwned + Send + 'static,
    R: Send + 'static,
{
    type Response = R;
    type Error = lambda_runtime::Error;
    type Future = BoxFuture<Result<R, lambda_runtime::Error>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, event: LambdaEvent<Box<RawValue>>) -> Self::Future {
        let cold_start = self.take_cold_start();
        let provider = self.provider.clone();
        let invocation = Invocation::start(&self.tracer, &event.context, cold_start);
        let typed_payload = match serde_json::from_str::<E>(event.payload.get()) {
            Ok(payload) => payload,
            Err(err) => {
                return Box::pin(async move {
                    let result: Result<R, lambda_runtime::Error> = Err(err.into());
                    let result = invocation.finish(result);
                    flush_provider(&provider);
                    result
                });
            }
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = self.inner.call(typed_event);
        Box::pin(async move {
            let result = fut.with_context(invocation.handler_context()).await;
            let result = invocation.finish(result.map_err(Into::into));
            flush_provider(&provider);
            result
        })
    }
}

fn flush_provider(provider: &opentelemetry_sdk::trace::SdkTracerProvider) {
    if let Err(err) = provider.force_flush() {
        tracing::error!("flush failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn noop_handler(
        _: LambdaEvent<serde_json::Value>,
    ) -> std::future::Ready<Result<(), lambda_runtime::Error>> {
        std::future::ready(Ok(()))
    }

    #[allow(clippy::type_complexity)]
    fn test_handler() -> WrappedHandler<ReadyService, serde_json::Value, ()> {
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, TRACER_NAME);
        WrappedHandler {
            inner: ReadyService,
            provider,
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
        let mut wrapped = WrappedHandler::new(
            ReadyCountingService {
                ready_calls: Arc::clone(&ready_calls),
            },
            Config::default(),
        );
        let waker = std::task::Waker::noop();
        let mut cx = task::Context::from_waker(waker);

        assert!(wrapped.poll_ready(&mut cx).is_ready());
        assert_eq!(ready_calls.load(Ordering::Relaxed), 1);
    }
}
