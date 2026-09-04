// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Panic and unwrap are banned in production code to prevent tracing from crashing
// customer AWS calls. Tests are exempt so they can use `.unwrap()` freely.
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

//! Shared AWS SDK request-span support for the Datadog AWS service instrumentation crates.
//!
//! This crate does not install instrumentation directly. Service-specific crates use it to:
//!
//! - create an OpenTelemetry client span for each AWS SDK operation as a child of the current
//!   OpenTelemetry context;
//! - tag the span with common AWS metadata, including service, operation, region, partition,
//!   resource name, and client span kind;
//! - expose the started request span context so service crates can inject trace context into
//!   supported AWS payloads;
//! - add final HTTP request attributes once the SDK request has been serialized;
//! - record response status, AWS request ID, SDK errors, and end the span after execution.

/// Shared attribute-key constants used by the AWS instrumentation crates.
pub mod attribute_keys;
mod request_span;

pub use request_span::{
    finish_request_span, request_span_context, request_span_trace_headers, start_request_span,
    update_request_span, AwsRequestMetadata,
};
