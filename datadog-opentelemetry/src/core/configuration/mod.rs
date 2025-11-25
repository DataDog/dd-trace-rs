// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Datadog tracing setup
//!
//! # Sources of configuration
//!
//! ```text
//! ^ Highest precedence
//! |
//! * Opentelemetry Resource object
//! |
//! * ConfigBuilder setters
//! |
//! * "DD" prefixed env variables
//! |
//! * Default values
//! |
//! v Lowest level of precedence
//! ```

#[allow(clippy::module_inception)]
mod configuration;
pub(crate) mod remote_config;
mod sources;
mod supported_configurations;

pub use configuration::{Config, ConfigBuilder, SamplingRuleConfig, TracePropagationStyle};
pub(crate) use configuration::{ConfigurationProvider, RemoteConfigUpdate};
