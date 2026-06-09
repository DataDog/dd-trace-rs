// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

// Panic and unwrap are banned in production code to prevent tracing from crashing
// customer AWS calls. Tests are exempt so they can use `.unwrap()` freely.
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]

pub mod attribute_keys;
mod request_span;

pub use request_span::{
    finish_request_span, request_span_trace_headers, start_request_span, update_request_span,
    AwsRequestMetadata,
};
