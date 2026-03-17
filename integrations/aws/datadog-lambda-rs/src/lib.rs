// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod invocation;
mod span_inferrer;

use invocation::{run_in_invocation_scope, start_invocation};
use lambda_runtime::{
    tower::{Layer, Service},
    LambdaEvent,
};
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

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
            Ok(p) => p,
            Err(e) => return Box::pin(async move { Err(e.into()) }),
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = handler(typed_event);
        Box::pin(async move { run_in_invocation_scope(scope, provider, fut).await })
    }
}

/// Tower `Layer` that applies Datadog Lambda tracing to a `tower::Service`.
pub struct DatadogLambdaLayer {
    provider: SdkTracerProvider,
    config: Arc<Config>,
}

impl DatadogLambdaLayer {
    pub fn new(provider: SdkTracerProvider) -> Self {
        Self {
            provider,
            config: Arc::new(Config::default()),
        }
    }

    pub fn with_config(provider: SdkTracerProvider, config: Config) -> Self {
        Self {
            provider,
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for DatadogLambdaLayer {
    type Service = DatadogLambdaService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DatadogLambdaService {
            inner,
            provider: self.provider.clone(),
            config: Arc::clone(&self.config),
            _phantom: PhantomData,
        }
    }
}

#[doc(hidden)]
pub struct DatadogLambdaService<S, E = Value> {
    inner: S,
    provider: SdkTracerProvider,
    config: Arc<Config>,
    _phantom: PhantomData<fn(LambdaEvent<E>)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_provider() -> SdkTracerProvider {
        SdkTracerProvider::builder().build()
    }

    #[test]
    fn layer_new_does_not_panic() {
        let _layer = DatadogLambdaLayer::new(bare_provider());
    }

    #[test]
    fn layer_with_config_does_not_panic() {
        let _layer = DatadogLambdaLayer::with_config(bare_provider(), Config::default());
    }
}

impl<S, E> Service<LambdaEvent<Value>> for DatadogLambdaService<S, E>
where
    S: Service<LambdaEvent<E>> + Send + 'static,
    S::Future: Send + 'static,
    S::Response: Send + 'static,
    S::Error: From<serde_json::Error> + std::fmt::Display + Send + 'static,
    E: DeserializeOwned + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, event: LambdaEvent<Value>) -> Self::Future {
        let provider = self.provider.clone();
        let config = Arc::clone(&self.config);
        let scope = start_invocation(&event, &provider, &config);
        let typed_payload = match serde_json::from_value::<E>(event.payload) {
            Ok(p) => p,
            Err(e) => return Box::pin(async move { Err(e.into()) }),
        };
        let typed_event = LambdaEvent::new(typed_payload, event.context);
        let fut = self.inner.call(typed_event);
        Box::pin(async move { run_in_invocation_scope(scope, provider, fut).await })
    }
}
