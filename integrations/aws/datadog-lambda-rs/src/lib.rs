// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog Lambda tracing for Rust.
//!
//! Provides instrumentation for AWS Lambda functions using the Datadog
//! Lambda extension for trace context propagation and span management.
//!
//! # Usage
//!
//! ```ignore
//! use datadog_lambda_rs::wrap_handler;
//! use lambda_runtime::{service_fn, Error, LambdaEvent};
//! use serde_json::Value;
//!
//! async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
//!     Ok(Value::Null)
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     let provider = /* configure your SdkTracerProvider */;
//!     lambda_runtime::run(service_fn(wrap_handler(handler, provider))).await
//! }
//! ```

use lambda_runtime::LambdaEvent;
use opentelemetry::Context;
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::Serialize;

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

pub struct InvocationContext {
    pub(crate) request_id: String,
    pub(crate) otel_cx: Context,
    pub(crate) parent_id: u64,
    pub(crate) sampling_priority: i32,
}

impl InvocationContext {
    pub fn otel_context(&self) -> &Context {
        &self.otel_cx
    }
}

#[must_use = "the returned InvocationContext must be used to parent child spans"]
pub async fn create_root_span<E: Serialize>(
    _request_id: &str,
    _event: &LambdaEvent<E>,
) -> InvocationContext {
    todo!()
}

pub async fn end_root_span(_ctx: &InvocationContext, _is_error: bool) {
    todo!()
}

pub fn wrap_handler<F, Fut, E, R>(
    _handler: F,
    _provider: SdkTracerProvider,
) -> impl Fn(LambdaEvent<E>) -> BoxFuture<Result<R, lambda_runtime::Error>>
where
    F: Fn(LambdaEvent<E>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<R, lambda_runtime::Error>> + Send + 'static,
    E: Serialize + Send + Sync + 'static,
    R: Send + 'static,
{
    |_event: LambdaEvent<E>| -> BoxFuture<Result<R, lambda_runtime::Error>> {
        Box::pin(async { todo!() })
    }
}
