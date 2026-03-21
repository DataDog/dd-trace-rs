// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod attribute_keys;
mod invocation;
mod span_inferrer;

use invocation::{run_in_invocation_scope, start_invocation};
use lambda_runtime::LambdaEvent;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;
type HandlerError = lambda_runtime::Error;

#[derive(Default)]
pub struct Config {
    /// Service name. Overrides `DD_SERVICE`. Ignored when [`tracing`](Self::tracing) is `Some`.
    pub service: Option<String>,
    /// Deployment environment. Overrides `DD_ENV`. Ignored when [`tracing`](Self::tracing) is `Some`.
    pub env: Option<String>,
    /// Service version. Overrides `DD_VERSION`. Ignored when [`tracing`](Self::tracing) is `Some`.
    pub version: Option<String>,
    /// Full control over the OTel SDK and Datadog tracer config. Power-user escape hatch.
    ///
    /// When `None` (default), Lambda-appropriate defaults are applied and `service`/`env`/`version`
    /// above are forwarded. When `Some`, the builder is used as-is; `service`/`env`/`version` are
    /// ignored and you are responsible for setting:
    /// - `trace_stats_computation_enabled = false` (extension handles stats server-side)
    /// - `trace_writer_synchronous_write = true` (so `force_flush()` blocks)
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

/// Wraps a Lambda handler with Datadog tracing.
///
/// Owns the [`SdkTracerProvider`](opentelemetry_sdk::trace::SdkTracerProvider) lifecycle and
/// applies Lambda-appropriate defaults automatically.
///
/// # Examples
///
/// ```ignore
/// // Zero-config
/// lambda_runtime::run(service_fn(wrap_handler(my_handler, Config::default()))).await
///
/// // Set service/env/version
/// lambda_runtime::run(service_fn(wrap_handler(my_handler, Config {
///     service: Some("my-service".into()),
///     env: Some("prod".into()),
///     ..Default::default()
/// }))).await
///
/// // Full tracer control
/// lambda_runtime::run(service_fn(wrap_handler(my_handler, Config {
///     tracing: Some(
///         datadog_opentelemetry::tracing()
///             .with_config(/* ... */)
///             .with_span_processor(MyProcessor),
///     ),
///     ..Default::default()
/// }))).await
/// ```
pub fn wrap_handler<F, Fut, E, R>(
    handler: F,
    config: Config,
) -> impl Fn(LambdaEvent<Value>) -> BoxFuture<Result<R, HandlerError>>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, HandlerError>> + Send + 'static,
    E: DeserializeOwned + Send + Sync + 'static,
    R: Send + 'static,
{
    let tracing = config.tracing;
    let service = config.service;
    let env = config.env;
    let version = config.version;
    let (provider, _propagator) = tracing
        .unwrap_or_else(|| build_tracing(service, env, version))
        .init_local();

    let handler = Arc::new(handler);
    let lambda_config = Arc::new(Config::default());
    move |event: LambdaEvent<Value>| {
        let handler = Arc::clone(&handler);
        let provider = provider.clone();
        let lambda_config = Arc::clone(&lambda_config);
        let scope = start_invocation(&event, &provider, &lambda_config);
        let typed_payload = match serde_json::from_value::<E>(event.payload) {
            Ok(payload) => payload,
            Err(err) => {
                return Box::pin(async move {
                    run_in_invocation_scope(scope, provider, async move { Err(err.into()) }).await
                });
            }
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = handler(typed_event);
        Box::pin(async move { run_in_invocation_scope(scope, provider, fut).await })
    }
}
