// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog sampling logic

pub(crate) mod otel_mappings;
pub(crate) mod utils;

// Re-export from libdd-sampling
pub use libdd_sampling::{
    AttributeFactory, AttributeLike, DatadogSampler, SamplingData, SamplingRule,
    SamplingRulesCallback, SpanProperties, TraceIdLike, ValueLike,
};

// Re-export key public types
pub use otel_mappings::{OtelAttributeFactory, OtelSamplingData};
