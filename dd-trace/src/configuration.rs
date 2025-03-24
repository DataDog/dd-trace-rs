// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, sync::OnceLock};

pub const TRACER_VERSION: &str = "0.0.1";

#[derive(Debug, Default)]
#[non_exhaustive]
/// The log level for the tracer
pub enum TracerLogLevel {
    Debug,
    Warn,
    #[default]
    Error,
}

#[derive(Debug)]
#[non_exhaustive]
/// Configuration for the Datadog Tracer
///
/// This represents the finalized configuration, some of the values are derived from each other
///
/// TODO(paullgdc): We probably want to have a system of mutliple sources and we get config in order
/// of source                 precedence. We also want to keep the origin of the configuration to
/// report it to telemetry.                 But for now, Default() + getenv is good enough.
pub struct Config {
    // # Global
    runtime_id: &'static str,

    // # Tracer
    tracer_version: &'static str,
    language_version: &'static str,

    // # Service tagging
    env: Option<String>,
    service: Option<String>,
    version: Option<String>,

    // # Agent
    /// A list of default tags to be added to every span
    /// If DD_ENV or DD_VERSION is used, it overrides any env or version tag defined in DD_TAGS
    tags: Vec<String>,
    /// url of the trace agent
    trace_agent_url: Cow<'static, str>,
    /// url of the dogstatsd agent
    dogstatsd_agent_url: Cow<'static, str>,

    // # Tracing
    /// Maximum number of spans to sample per second, per process
    /// if this is not set, the datadog Agent controls rate limiting
    trace_rate_limit: Option<f64>,
    /// Disables the library if this is false
    trace_enabled: bool,
    /// The log level for the tracer
    log_level: TracerLogLevel,
}

impl Config {
    pub fn runtime_id(&self) -> &str {
        self.runtime_id
    }

    pub fn tracer_version(&self) -> &str {
        self.tracer_version
    }

    pub fn language_version(&self) -> &str {
        self.language_version
    }

    pub fn env(&self) -> Option<&str> {
        self.env.as_deref()
    }

    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().map(String::as_str)
    }

    pub fn trace_agent_url(&self) -> &Cow<'static, str> {
        &self.trace_agent_url
    }

    pub fn dogstatsd_agent_url(&self) -> &Cow<'static, str> {
        &self.dogstatsd_agent_url
    }

    pub fn trace_rate_limit(&self) -> Option<f64> {
        self.trace_rate_limit
    }

    pub fn trace_enabled(&self) -> bool {
        self.trace_enabled
    }

    pub fn log_level(&self) -> &TracerLogLevel {
        &self.log_level
    }

    fn process_runtime_id() -> &'static str {
        // TODO(paullgdc): Regenerate on fork? Would we even support forks?
        static RUNTIME_ID: OnceLock<String> = OnceLock::new();
        RUNTIME_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            runtime_id: Config::process_runtime_id(),
            env: None,
            service: None,
            version: None,
            tags: Vec::new(),

            trace_agent_url: Cow::Borrowed("http://localhost:8126"),
            dogstatsd_agent_url: Cow::Borrowed("http://localhost:8125"),
            trace_rate_limit: None,
            trace_enabled: true,
            log_level: TracerLogLevel::default(),
            tracer_version: TRACER_VERSION,
            language_version: "TODO: Get from env",
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_empty() {
        // TODO: Remove when we start commiting real code
    }
}
