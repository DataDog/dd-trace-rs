// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog instrumentation for AWS SDK for Rust.
//!
//! Provides automatic trace context injection for AWS SDK requests,
//! enabling distributed tracing across SQS, SNS, and EventBridge.
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_aws::AwsInterceptor;
//!
//! let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
//!     .interceptor(AwsInterceptor::new())
//!     .build();
//! let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
//! ```

mod attribute_keys;
mod interceptor;
mod services;

pub use interceptor::AwsInterceptor;
