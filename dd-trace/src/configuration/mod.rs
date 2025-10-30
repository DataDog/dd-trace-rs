// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::module_inception)]
mod configuration;
pub mod remote_config;
mod sources;
mod supported_configurations;

pub use configuration::{
    Config, ConfigBuilder, ConfigurationProvider, RemoteConfigUpdate, SamplingRuleConfig,
    TracePropagationStyle,
};
