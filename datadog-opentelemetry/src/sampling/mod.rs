// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog sampling logic
//!
//! Core sampling types and algorithms are provided by `libdd_sampling`.
//! This module re-exports the key types and provides OpenTelemetry-specific
//! adapters (OTel span → sampling trait impls).

pub(crate) mod otel_mappings;
pub(crate) mod utils;

// Re-export key public types from libdd-sampling
pub use libdd_sampling::{DatadogSampler, SamplingRule, SamplingRulesCallback};
pub use otel_mappings::{OtelAttributeFactory, OtelSamplingData};

// Re-export trait only needed by benchmarks (external to this crate)
#[cfg(feature = "test-utils")]
pub use libdd_sampling::SamplingData;
