// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod attribute_keys;
mod invocation;
mod span_inferrer;

use invocation::{run_in_invocation_scope, start_invocation};
use lambda_runtime::LambdaEvent;
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::Arc;

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;
type HandlerError = lambda_runtime::Error;

/// Configuration for datadog-lambda-rs instrumentation.
#[derive(Default)]
pub struct Config {}

/// Wrap a handler function with Datadog Lambda tracing using default config.
pub fn wrap_handler<F, Fut, E, R>(
    handler: F,
    provider: SdkTracerProvider,
) -> impl Fn(LambdaEvent<Value>) -> BoxFuture<Result<R, HandlerError>>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, HandlerError>> + Send + 'static,
    E: DeserializeOwned + Send + Sync + 'static,
    R: Send + 'static,
{
    wrap_handler_with_config(handler, provider, Config::default())
}

/// Wrap a handler function with Datadog Lambda tracing using custom config.
pub fn wrap_handler_with_config<F, Fut, E, R>(
    handler: F,
    provider: SdkTracerProvider,
    config: Config,
) -> impl Fn(LambdaEvent<Value>) -> BoxFuture<Result<R, HandlerError>>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, HandlerError>> + Send + 'static,
    E: DeserializeOwned + Send + Sync + 'static,
    R: Send + 'static,
{
    let handler = Arc::new(handler);
    let config = Arc::new(config);
    move |event: LambdaEvent<Value>| {
        let handler = Arc::clone(&handler);
        let provider = provider.clone();
        let config = Arc::clone(&config);
        let scope = start_invocation(&event, &provider, &config);
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
