// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::Cow, ops::Deref, str::FromStr, sync::OnceLock};

use super::sources::{CompositeConfigSourceResult, CompositeSource};

pub const TRACER_VERSION: &str = "0.0.1";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// The level at which the library will log
pub enum LogLevel {
    Debug,
    Warn,
    #[default]
    Error,
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("debug") {
            Ok(LogLevel::Debug)
        } else if s.eq_ignore_ascii_case("warn") {
            Ok(LogLevel::Warn)
        } else if s.eq_ignore_ascii_case("error") {
            Ok(LogLevel::Error)
        } else {
            Err("log level should be one of DEBUG, WARN, ERROR")
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// Configuration for the Datadog Tracer
// TODO(paullgdc): We also want to keep the origin of each of configuration, and the errors
// encountered during parsing to report it to telemetry.
///
/// # Usage
/// ```
/// use dd_trace::Config;
///
/// // This pulls configuration from the environment and other sources
/// let mut builder = Config::builder();
///
/// // Manual overrides
/// builder
///     .set_service("my-service".to_string())
///     .set_version("1.0.0".to_string());
///
/// // Finalize the configuratiom
/// let config = builder.build();
/// ```
pub struct Config {
    // # Global
    runtime_id: &'static str,

    // # Tracer
    tracer_version: &'static str,
    language_version: &'static str,

    // # Service tagging
    service: String,
    env: Option<String>,
    version: Option<String>,

    // # Agent
    /// A list of default tags to be added to every span
    /// If DD_ENV or DD_VERSION is used, it overrides any env or version tag defined in DD_TAGS
    global_tags: Vec<String>,
    /// url of the trace agent
    trace_agent_url: Cow<'static, str>,
    /// url of the dogstatsd agent
    dogstatsd_agent_url: Cow<'static, str>,

    // # Tracing
    /// Maximum number of spans to sample per second, per process
    /// if this is not set, the datadog Agent controls rate limiting
    trace_rate_limit: Option<f64>,
    /// JSON configuration string for sampling rules
    trace_sampling_rules: Option<String>,

    /// Disables the library if this is false
    enabled: bool,
    /// The log level for the tracer
    log_level: LogLevel,

    /// Configurations for testing. Not exposed to customer
    #[cfg(feature = "test-utils")]
    wait_agent_info_ready: bool,
}

impl Config {
    fn from_sources(sources: &CompositeSource) -> Self {
        let default = Config::default();

        /// Helper function to convert a CompositeConfigSourceResult<T> into an Option<T>
        /// This drops errors origin associated with the configuration collected while parsing the
        /// value
        ///
        /// TODO(paullgdc): We should store the error, and the origin of the configuration
        /// in the Config struct, so we can report it to telemetry.
        fn to_val<T>(res: CompositeConfigSourceResult<T>) -> Option<T> {
            res.value.map(|c| c.value)
        }

        /// Wrapper to parse "," separated string to vector
        struct DdTags(Vec<String>);

        impl FromStr for DdTags {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(DdTags(
                    s.split(',').map(|s| s.to_string()).collect::<Vec<String>>(),
                ))
            }
        }

        Self {
            runtime_id: default.runtime_id,
            tracer_version: default.tracer_version,
            language_version: default.language_version,
            service: to_val(sources.get("DD_SERVICE")).unwrap_or(default.service),
            env: to_val(sources.get("DD_ENV")).or(default.env),
            version: to_val(sources.get("DD_VERSION")).or(default.version),
            // TODO(paullgdc): tags should be merged, not replaced
            global_tags: to_val(sources.get_parse::<DdTags>("DD_TAGS"))
                .map(|DdTags(tags)| tags)
                .unwrap_or(default.global_tags),
            trace_agent_url: to_val(sources.get("DD_TRACE_AGENT_URL"))
                .map(Cow::Owned)
                .unwrap_or(default.trace_agent_url),
            dogstatsd_agent_url: default.dogstatsd_agent_url,
            trace_rate_limit: to_val(sources.get_parse("DD_TRACE_RATE_LIMIT"))
                .or(default.trace_rate_limit),
            trace_sampling_rules: to_val(sources.get("DD_TRACE_SAMPLING_RULES"))
                .or(default.trace_sampling_rules),
            enabled: to_val(sources.get_parse("DD_TRACE_ENABLED")).unwrap_or(default.enabled),
            log_level: to_val(sources.get_parse("DD_LOG_LEVEL")).unwrap_or(default.log_level),
            #[cfg(feature = "test-utils")]
            wait_agent_info_ready: default.wait_agent_info_ready,
        }
    }

    fn builder_with_sources(sources: &CompositeSource) -> ConfigBuilder {
        ConfigBuilder {
            config: Config::from_sources(sources),
        }
    }

    /// Creates a new builder to set overrides detected configuration
    pub fn builder() -> ConfigBuilder {
        Self::builder_with_sources(&CompositeSource::default_sources())
    }

    pub fn runtime_id(&self) -> &str {
        self.runtime_id
    }

    pub fn tracer_version(&self) -> &str {
        self.tracer_version
    }

    pub fn language_version(&self) -> &str {
        self.language_version
    }

    pub fn service(&self) -> &str {
        self.service.deref()
    }

    pub fn env(&self) -> Option<&str> {
        self.env.as_deref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn global_tags(&self) -> impl Iterator<Item = &str> {
        self.global_tags.iter().map(String::as_str)
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

    pub fn trace_sampling_rules(&self) -> Option<&str> {
        self.trace_sampling_rules.as_deref()
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn log_level(&self) -> &LogLevel {
        &self.log_level
    }

    #[cfg(feature = "test-utils")]
    pub fn __internal_wait_agent_info_ready(&self) -> bool {
        self.wait_agent_info_ready
    }

    /// Static runtime id if the process
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
            // TODO(paulgdc): Default service naming detection, probably from arg0
            service: "unnamed-rust-service".to_string(),
            version: None,
            global_tags: Vec::new(),

            trace_agent_url: Cow::Borrowed("http://localhost:8126"),
            dogstatsd_agent_url: Cow::Borrowed("http://localhost:8125"),
            trace_rate_limit: None,
            trace_sampling_rules: None,
            enabled: true,
            log_level: LogLevel::default(),
            tracer_version: TRACER_VERSION,
            language_version: "TODO: Get from env",
            #[cfg(feature = "test-utils")]
            wait_agent_info_ready: false,
        }
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Finalizes the builder and returns the configuration
    pub fn build(self) -> Config {
        self.config
    }

    pub fn set_service(&mut self, service: String) -> &mut Self {
        self.config.service = service;
        self
    }

    pub fn set_env(&mut self, env: String) -> &mut Self {
        self.config.env = Some(env);
        self
    }

    pub fn set_version(&mut self, version: String) -> &mut Self {
        self.config.version = Some(version);
        self
    }

    pub fn set_global_tags(&mut self, tags: Vec<String>) -> &mut Self {
        self.config.global_tags = tags;
        self
    }

    pub fn add_global_tag(&mut self, tag: String) -> &mut Self {
        self.config.global_tags.push(tag);
        self
    }

    pub fn set_trace_agent_url(&mut self, url: Cow<'static, str>) -> &mut Self {
        self.config.trace_agent_url = Cow::Owned(url.to_string());
        self
    }

    pub fn set_trace_rate_limit(&mut self, rate_limit: f64) -> &mut Self {
        self.config.trace_rate_limit = Some(rate_limit);
        self
    }

    pub fn set_trace_sampling_rules(&mut self, rules_json: String) -> &mut Self {
        self.config.trace_sampling_rules = Some(rules_json);
        self
    }

    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.enabled = enabled;
        self
    }

    pub fn set_log_level(&mut self, log_level: LogLevel) -> &mut Self {
        self.config.log_level = log_level;
        self
    }

    #[cfg(feature = "test-utils")]
    pub fn __internal_set_wait_agent_info_ready(
        &mut self,
        wait_agent_info_ready: bool,
    ) -> &mut Self {
        self.config.wait_agent_info_ready = wait_agent_info_ready;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::configuration::sources::{CompositeSource, ConfigSourceOrigin, HashMapSource};

    #[test]
    fn test_config_from_source() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_SERVICE", "test-service"),
                ("DD_ENV", "test-env"),
                ("DD_VERSION", "x.y.z"),
                ("DD_TAGS", "abc:def,foo:bar"),
                ("DD_TRACE_AGENT_URL", "http://localhost:1234"),
                ("DD_TRACE_RATE_LIMIT", "100"),
                ("DD_TRACE_ENABLED", "false"),
                ("DD_LOG_LEVEL", "DEBUG"),
                (
                    "DD_TRACE_SAMPLING_RULES",
                    r#"{"rules":[{"sample_rate":0.5,"service":"web-api"}]}"#,
                ),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.service(), "test-service");
        assert_eq!(config.env(), Some("test-env"));
        assert_eq!(config.version(), Some("x.y.z"));
        assert_eq!(
            config.global_tags().collect::<Vec<_>>(),
            vec!["abc:def", "foo:bar"]
        );
        assert_eq!(config.trace_agent_url(), "http://localhost:1234");
        assert_eq!(config.trace_rate_limit(), Some(100.0));
        assert!(!config.enabled());
        assert_eq!(config.log_level(), &super::LogLevel::Debug);
        assert_eq!(
            config.trace_sampling_rules(),
            Some(r#"{"rules":[{"sample_rate":0.5,"service":"web-api"}]}"#)
        );
    }

    #[test]
    fn test_config_from_source_manual_override() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_SERVICE", "test-service"),
                ("DD_ENV", "test-env"),
                ("DD_VERSION", "x.y.z"),
                ("DD_TAGS", "abc:def,foo:bar"),
                ("DD_TRACE_AGENT_URL", "http://localhost:1234"),
                ("DD_TRACE_RATE_LIMIT", "100"),
                ("DD_TRACE_ENABLED", "false"),
                ("DD_LOG_LEVEL", "DEBUG"),
                (
                    "DD_TRACE_SAMPLING_RULES",
                    r#"{"rules":[{"sample_rate":0.5,"service":"web-api"}]}"#,
                ),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let mut builder = Config::builder_with_sources(&sources);
        builder.set_service("manual-service".to_string());
        builder.set_env("manual-env".to_string());
        builder.set_version("manual-version".to_string());
        builder.set_global_tags(vec!["manual:tag".to_string()]);
        builder.add_global_tag("another:tag".to_string());
        builder.set_trace_agent_url("http://localhost:4321".into());
        builder.set_trace_rate_limit(200.0);
        builder.set_enabled(true);
        builder.set_log_level(super::LogLevel::Warn);
        builder.set_trace_sampling_rules(r#"{"rules":[{"sample_rate":0.8,"service":"my-service"}]}"#.to_string());

        let config = builder.build();

        assert_eq!(config.service(), "manual-service");
        assert_eq!(config.env(), Some("manual-env"));
        assert_eq!(config.version(), Some("manual-version"));
        assert_eq!(
            config.global_tags().collect::<Vec<_>>(),
            vec!["manual:tag", "another:tag"]
        );
        assert_eq!(config.trace_agent_url(), "http://localhost:4321");
        assert_eq!(config.trace_rate_limit(), Some(200.0));
        assert!(config.enabled());
        assert_eq!(config.log_level(), &super::LogLevel::Warn);
        assert_eq!(
            config.trace_sampling_rules(),
            Some(r#"{"rules":[{"sample_rate":0.8,"service":"my-service"}]}"#)
        );
    }
}
