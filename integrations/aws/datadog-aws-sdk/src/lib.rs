// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog trace context propagation for AWS SDK for Rust.
//!
//! Provides automatic trace context injection for AWS SDK requests, enabling
//! distributed tracing across AWS services.
//!
//! # Usage
//!
//! ```rust,ignore
//! use aws_config::BehaviorVersion;
//! use datadog_aws_sdk::instrument_config;
//!
//! let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
//! let config = instrument_config(config);
//!
//! // All clients created from this config are automatically traced
//! let sqs_client = aws_sdk_sqs::Client::new(&config);
//! sqs_client.send_message().send().await?;
//! ```
//!
//! # Service-Specific Behavior
//!
//! The interceptor automatically detects the AWS service and injects trace context:
//!
//! - **SQS**: `MessageAttributes` with `DataType: String`
//! - **SNS**: `MessageAttributes` with `DataType: Binary`
//! - **Kinesis**: Record data injection
//! - **EventBridge**: `Detail` field with timestamp and resource name
//! - **Other services**: HTTP headers

pub mod interceptor;
mod services;

pub use interceptor::DatadogTracePropagationInterceptor;

/// Instruments an AWS SDK config with Datadog trace propagation.
///
/// # Example
///
/// ```rust,ignore
/// let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
/// let config = datadog_aws_sdk::instrument_config(config);
///
/// let sqs_client = aws_sdk_sqs::Client::new(&config);
/// ```
pub fn instrument_config(config: aws_types::SdkConfig) -> aws_types::SdkConfig {
    // TODO: Add interceptor to config's runtime components
    config
}
