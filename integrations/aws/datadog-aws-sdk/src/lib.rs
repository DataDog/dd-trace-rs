// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog trace context propagation for AWS SDK for Rust
//!
//! This crate provides automatic trace context injection for AWS SDK requests,
//! enabling distributed tracing across AWS services.
//!
//! # Architecture
//!
//! Similar to dd-trace-go's `contrib/aws/aws-sdk-go-v2` package, this crate:
//! - Provides an AWS SDK interceptor for automatic trace propagation
//! - Supports both Datadog and W3C trace context formats
//! - Handles service-specific context injection (SQS, SNS, EventBridge)
//!
//! # Example
//!
//! ```rust,ignore
//! use aws_config::BehaviorVersion;
//! use aws_sdk_sqs::Client;
//! use datadog_aws_sdk::DatadogTracePropagationInterceptor;
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
//!     let sqs_client = Client::new(&config);
//!
//!     // Use per-operation
//!     sqs_client
//!         .send_message()
//!         .queue_url("https://sqs.us-east-1.amazonaws.com/123/my-queue")
//!         .message_body("Hello")
//!         .customize()
//!         .interceptor(DatadogTracePropagationInterceptor::new())
//!         .send()
//!         .await?;
//! }
//! ```
//!
//! # Design Philosophy
//!
//! Following dd-trace-go's approach:
//! - **Opt-in**: Users explicitly add this crate as a dependency
//! - **Modular**: Separate from core datadog-opentelemetry library
//! - **Simple API**: Single interceptor that works with all AWS services
//! - **Automatic**: Parent span inheritance via OpenTelemetry context

pub mod interceptor;

pub use interceptor::DatadogTracePropagationInterceptor;
