// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Core sampling logic for Datadog tracing
//!
//! This crate provides generic sampling infrastructure including:
//! - Trait abstractions for trace IDs, attributes, and span properties
//! - Rate-based sampling algorithms
//! - Rate limiting functionality
//! - Glob pattern matching for sampling rules
//! - Sampling-related constants
//! - Rule-based sampling with pattern matching
//! - Agent-provided sampling rates
//! - Complete Datadog sampler implementation

pub mod agent_service_sampler;
pub mod constants;
pub mod datadog_sampler;
pub mod dd_constants;
pub mod dd_sampling;
pub mod glob_matcher;
pub mod rate_limiter;
pub mod rate_sampler;
pub mod rules_sampler;
pub mod sampling_rule;
pub mod sampling_rule_config;
pub mod types;

// Re-export key types for convenience
pub use agent_service_sampler::ServicesSampler;
pub use datadog_sampler::{DatadogSampler, SamplingRulesCallback};
pub use dd_sampling::{mechanism, priority, SamplingDecision, SamplingMechanism, SamplingPriority};
pub use sampling_rule::SamplingRule;
pub use sampling_rule_config::{ParsedSamplingRules, SamplingRuleConfig};
pub use types::{
    AttributeFactory, AttributeLike, SamplingData, SpanProperties, TraceIdLike, ValueLike,
};
