// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog instrumentation for AWS SDK for Rust.
//!
//! Add [`DatadogAwsInterceptor`] when building a service client to automatically
//! inject Datadog trace context into SQS, SNS, and EventBridge calls.

mod interceptor;
mod services;

pub use interceptor::DatadogAwsInterceptor;
