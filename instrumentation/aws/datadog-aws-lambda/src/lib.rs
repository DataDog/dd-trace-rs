// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod attribute_keys;
mod invocation;
mod span_inferrer;

use invocation::Invocation;
use lambda_runtime::tower::Service;
use lambda_runtime::LambdaEvent;
use opentelemetry::trace::FutureExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
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
/// lambda_runtime::run(WrappedHandler::new(my_handler, Config::default())).await
///
/// // Set service/env/version
/// lambda_runtime::run(WrappedHandler::new(my_handler, Config {
///     service: Some("my-service".into()),
///     env: Some("prod".into()),
///     ..Default::default()
/// })).await
///
/// // Full tracer control
/// lambda_runtime::run(WrappedHandler::new(my_handler, Config {
///     tracing: Some(
///         datadog_opentelemetry::tracing()
///             .with_config(builder_config_here)
///             .with_span_processor(MyProcessor),
///     ),
///     ..Default::default()
/// })).await
///
/// // With tower middleware
/// lambda_runtime::run(
///     tower::ServiceBuilder::new()
///         .layer(some_middleware)
///         .service(WrappedHandler::new(my_handler, Config::default()))
/// ).await
/// ```
pub struct WrappedHandler<F, E, R> {
    inner: Arc<F>,
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
    cold_start: bool,
    _phantom: PhantomData<fn(E) -> R>,
}

impl<F, E, R> WrappedHandler<F, E, R> {
    pub fn new(handler: F, config: Config) -> Self {
        let Config {
            tracing,
            service,
            env,
            version,
        } = config;
        let provider = tracing
            .unwrap_or_else(|| build_tracing(service, env, version))
            .init();
        Self {
            inner: Arc::new(handler),
            provider,
            cold_start: true,
            _phantom: PhantomData,
        }
    }

    fn take_cold_start(&mut self) -> bool {
        std::mem::replace(&mut self.cold_start, false)
    }
}

impl<F, Fut, E, R> Service<LambdaEvent<Value>> for WrappedHandler<F, E, R>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<R, lambda_runtime::Error>> + Send + 'static,
    E: DeserializeOwned + Send + Sync + 'static,
    R: Send + 'static,
{
    type Response = R;
    type Error = lambda_runtime::Error;
    type Future = BoxFuture<Result<R, lambda_runtime::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, event: LambdaEvent<Value>) -> Self::Future {
        let cold_start = self.take_cold_start();
        let inner_handler = Arc::clone(&self.inner);
        let provider = self.provider.clone();
        let invocation = Invocation::start(&event, &provider, cold_start);
        let typed_payload = match serde_json::from_value::<E>(event.payload) {
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
        let fut = inner_handler(typed_event);
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

    fn noop_handler(
        _: LambdaEvent<Value>,
    ) -> std::future::Ready<Result<(), lambda_runtime::Error>> {
        std::future::ready(Ok(()))
    }

    fn test_handler() -> WrappedHandler<
        fn(LambdaEvent<Value>) -> std::future::Ready<Result<(), lambda_runtime::Error>>,
        Value,
        (),
    > {
        WrappedHandler {
            inner: Arc::new(noop_handler),
            provider: opentelemetry_sdk::trace::SdkTracerProvider::builder().build(),
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
}
