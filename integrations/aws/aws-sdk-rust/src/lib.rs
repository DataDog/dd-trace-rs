// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog trace context propagation for AWS SDK for Rust.
//!
//! Provides automatic trace context injection for AWS SDK requests, enabling
//! distributed tracing across AWS services.
//!
//! # Usage
//!
//! Add the interceptor when building your service client so all operations are
//! automatically traced:
//!
//! ```rust,ignore
//! use datadog_aws_sdk::DatadogInterceptor;
//!
//! let sdk_config = aws_config::defaults(BehaviorVersion::latest())
//!     .load()
//!     .await;
//! let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
//!     .interceptor(DatadogInterceptor::new())
//!     .build();
//! let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
//! ```

mod interceptor;
mod services;

pub use interceptor::DatadogInterceptor;
