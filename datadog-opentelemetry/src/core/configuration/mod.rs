// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Datadog tracing setup
//!
//! # Sources of configuration
//!
//! General precedence is: OpenTelemetry Resource object, `ConfigBuilder` setters, "DD"-prefixed
//! environment variables, then defaults. Environment uses a field-specific order:
//! `DD_ENV`/`ConfigBuilder::set_env`, Resource `deployment.environment.name` or
//! `deployment.environment`, `DD_TAGS[env]`, then `OTEL_RESOURCE_ATTRIBUTES`.

#[allow(clippy::module_inception)]
mod configuration;
pub(crate) mod remote_config;
mod sources;
mod supported_configurations;

pub use configuration::{
    BaggageTagKeyFilter, Config, ConfigBuilder, OtlpProtocol, TracePropagationBehaviorExtract,
    TracePropagationStyle,
};
pub(crate) use configuration::{ConfigParser, ConfigurationProvider, RemoteConfigUpdate};

mod sampling_rule_config;
pub use sampling_rule_config::{ParsedSamplingRules, SamplingRuleConfig};
