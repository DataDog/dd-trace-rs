// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{borrow::Cow, fmt::Display, ops::Deref, str::FromStr, sync::OnceLock};

use crate::dd_warn;
use crate::log::LevelFilter;

use super::sources::{CompositeConfigSourceResult, CompositeSource};

/// Configuration for a single sampling rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SamplingRuleConfig {
    /// The sample rate to apply (0.0-1.0)
    pub sample_rate: f64,

    /// Optional service name pattern to match
    #[serde(default)]
    pub service: Option<String>,

    /// Optional span name pattern to match
    #[serde(default)]
    pub name: Option<String>,

    /// Optional resource name pattern to match
    #[serde(default)]
    pub resource: Option<String>,

    /// Tags that must match (key-value pairs)
    #[serde(default)]
    pub tags: HashMap<String, String>,

    /// Where this rule comes from (customer, dynamic, default)
    // TODO(paullgdc): this value should not be definable by customers
    #[serde(default = "default_provenance")]
    pub provenance: String,
}

fn default_provenance() -> String {
    "default".to_string()
}

pub const TRACER_VERSION: &str = "0.0.1";

#[derive(Debug, Default)]
struct ParsedSamplingRules {
    rules: Vec<SamplingRuleConfig>,
}

impl FromStr for ParsedSamplingRules {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            return Ok(ParsedSamplingRules::default());
        }
        // DD_TRACE_SAMPLING_RULES is expected to be a JSON array of SamplingRuleConfig objects.
        let rules_vec: Vec<SamplingRuleConfig> = serde_json::from_str(s)?;
        Ok(ParsedSamplingRules { rules: rules_vec })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracePropagationStyle {
    Datadog,
    TraceContext,
    None,
}

impl TracePropagationStyle {
    fn from_tags(tags: Option<Vec<String>>) -> Option<Vec<TracePropagationStyle>> {
        match tags {
            Some(tags) if !tags.is_empty() => Some(
                tags.iter()
                    .filter_map(|value| match TracePropagationStyle::from_str(value) {
                        Ok(style) => Some(style),
                        Err(err) => {
                            dd_warn!("Error parsing: {err}");
                            None
                        }
                    })
                    .collect::<Vec<TracePropagationStyle>>(),
            ),
            Some(_) => None,
            None => None,
        }
    }
}

impl FromStr for TracePropagationStyle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "datadog" => Ok(TracePropagationStyle::Datadog),
            "tracecontext" => Ok(TracePropagationStyle::TraceContext),
            "none" => Ok(TracePropagationStyle::None),
            _ => Err(format!("Unknown trace propagation style: '{s}'")),
        }
    }
}

impl Display for TracePropagationStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let style = match self {
            TracePropagationStyle::Datadog => "datadog",
            TracePropagationStyle::TraceContext => "tracecontext",
            TracePropagationStyle::None => "none",
        };
        write!(f, "{style}")
    }
}

#[derive(Debug)]
#[non_exhaustive]
/// Configuration for the Datadog Tracer
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

    // # Sampling
    ///  A list of sampling rules. Each rule is matched against the root span of a trace
    /// If a rule matches, the trace is sampled with the associated sample rate.
    trace_sampling_rules: Vec<SamplingRuleConfig>,

    /// Maximum number of spans to sample per second
    /// Only applied if trace_sampling_rules are matched
    trace_rate_limit: i32,

    /// Disables the library if this is false
    enabled: bool,
    /// The log level filter for the tracer
    log_level_filter: LevelFilter,

    /// Whether to enable stats computation for the tracer
    /// Results in dropped spans not being sent to the agent
    trace_stats_computation_enabled: bool,

    /// Configurations for testing. Not exposed to customer
    #[cfg(feature = "test-utils")]
    wait_agent_info_ready: bool,

    /// Trace propagation configuration
    trace_propagation_style: Option<Vec<TracePropagationStyle>>,
    trace_propagation_style_extract: Option<Vec<TracePropagationStyle>>,
    trace_propagation_style_inject: Option<Vec<TracePropagationStyle>>,
    trace_propagation_extract_first: bool,
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

        let parsed_sampling_rules_config =
            to_val(sources.get_parse::<ParsedSamplingRules>("DD_TRACE_SAMPLING_RULES"));

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

            // Populate from parsed_sampling_rules_config or defaults
            trace_sampling_rules: parsed_sampling_rules_config
                .map(|psc| psc.rules)
                .unwrap_or(default.trace_sampling_rules),
            trace_rate_limit: to_val(sources.get_parse("DD_TRACE_RATE_LIMIT"))
                .unwrap_or(default.trace_rate_limit),

            enabled: to_val(sources.get_parse("DD_TRACE_ENABLED")).unwrap_or(default.enabled),
            log_level_filter: to_val(sources.get_parse("DD_LOG_LEVEL"))
                .unwrap_or(default.log_level_filter),
            trace_stats_computation_enabled: to_val(
                sources.get_parse("DD_TRACE_STATS_COMPUTATION_ENABLED"),
            )
            .unwrap_or(default.trace_stats_computation_enabled),
            trace_propagation_style: TracePropagationStyle::from_tags(
                to_val(sources.get_parse::<DdTags>("DD_TRACE_PROPAGATION_STYLE"))
                    .map(|DdTags(tags)| Some(tags))
                    .unwrap_or_default(),
            ),
            trace_propagation_style_extract: TracePropagationStyle::from_tags(
                to_val(sources.get_parse::<DdTags>("DD_TRACE_PROPAGATION_STYLE_EXTRACT"))
                    .map(|DdTags(tags)| Some(tags))
                    .unwrap_or_default(),
            ),
            trace_propagation_style_inject: TracePropagationStyle::from_tags(
                to_val(sources.get_parse::<DdTags>("DD_TRACE_PROPAGATION_STYLE_INJECT"))
                    .map(|DdTags(tags)| Some(tags))
                    .unwrap_or_default(),
            ),
            trace_propagation_extract_first: to_val(
                sources.get_parse("DD_TRACE_PROPAGATION_EXTRACT_FIRST"),
            )
            .unwrap_or(default.trace_propagation_extract_first),
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

    pub fn trace_sampling_rules(&self) -> &[SamplingRuleConfig] {
        self.trace_sampling_rules.as_ref()
    }

    pub fn trace_rate_limit(&self) -> i32 {
        self.trace_rate_limit
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn log_level_filter(&self) -> &LevelFilter {
        &self.log_level_filter
    }

    pub fn trace_stats_computation_enabled(&self) -> bool {
        self.trace_stats_computation_enabled
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

    pub fn trace_propagation_style(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style.as_deref()
    }

    pub fn trace_propagation_style_extract(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_extract.as_deref()
    }

    pub fn trace_propagation_style_inject(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_inject.as_deref()
    }

    pub fn trace_propagation_extract_first(&self) -> bool {
        self.trace_propagation_extract_first
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
            trace_sampling_rules: Vec::new(),
            trace_rate_limit: 100,
            enabled: true,
            log_level_filter: LevelFilter::default(),
            tracer_version: TRACER_VERSION,
            language_version: "TODO: Get from env",
            trace_stats_computation_enabled: true,
            #[cfg(feature = "test-utils")]
            wait_agent_info_ready: false,

            trace_propagation_style: None,
            trace_propagation_style_extract: None,
            trace_propagation_style_inject: None,
            trace_propagation_extract_first: false,
        }
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Finalizes the builder and returns the configuration
    pub fn build(self) -> Config {
        crate::log::set_max_level(self.config.log_level_filter);
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

    pub fn set_trace_sampling_rules(&mut self, rules: Vec<SamplingRuleConfig>) -> &mut Self {
        self.config.trace_sampling_rules = rules;
        self
    }

    pub fn set_trace_rate_limit(&mut self, rate_limit: i32) -> &mut Self {
        self.config.trace_rate_limit = rate_limit;
        self
    }

    pub fn set_trace_propagation_style(&mut self, styles: Vec<TracePropagationStyle>) -> &Self {
        self.config.trace_propagation_style = Some(styles);
        self
    }

    pub fn set_trace_propagation_style_extract(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &Self {
        self.config.trace_propagation_style_extract = Some(styles);
        self
    }

    pub fn set_trace_propagation_style_inject(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &Self {
        self.config.trace_propagation_style_inject = Some(styles);
        self
    }

    pub fn set_trace_propagation_extract_first(&mut self, first: bool) -> &Self {
        self.config.trace_propagation_extract_first = first;
        self
    }

    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.enabled = enabled;
        self
    }

    pub fn set_log_level_filter(&mut self, filter: LevelFilter) -> &mut Self {
        self.config.log_level_filter = filter;
        self
    }

    pub fn set_trace_stats_computation_enabled(
        &mut self,
        trace_stats_computation_enabled: bool,
    ) -> &mut Self {
        self.config.trace_stats_computation_enabled = trace_stats_computation_enabled;
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
    use super::*;
    use crate::configuration::sources::{CompositeSource, ConfigSourceOrigin, HashMapSource};

    #[test]
    fn test_config_from_source() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_SERVICE", "test-service"),
                ("DD_ENV", "test-env"),
                ("DD_TRACE_SAMPLING_RULES", 
                 r#"[{"sample_rate":0.5,"service":"web-api","name":null,"resource":null,"tags":{},"provenance":"customer"}]"#),
                ("DD_TRACE_RATE_LIMIT", "123"),
                ("DD_TRACE_ENABLED", "true"),
                ("DD_LOG_LEVEL", "DEBUG"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.service(), "test-service");
        assert_eq!(config.env(), Some("test-env"));
        assert_eq!(config.trace_rate_limit(), 123);
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1, "Should have one rule");
        assert_eq!(
            &rules[0],
            &SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("web-api".to_string()),
                provenance: "customer".to_string(),
                ..SamplingRuleConfig::default()
            }
        );

        assert!(config.enabled());
        assert_eq!(config.log_level_filter(), &super::LevelFilter::Debug);
    }

    #[test]
    fn test_sampling_rules() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [(
                "DD_TRACE_SAMPLING_RULES",
                r#"[{"sample_rate":0.5,"service":"test-service","provenance":"customer"}]"#,
            )],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(
            &config.trace_sampling_rules()[0],
            &SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("test-service".to_string()),
                provenance: "customer".to_string(),
                ..SamplingRuleConfig::default()
            }
        );
    }

    #[test]
    fn test_config_from_source_manual_override() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_SERVICE", "test-service"),
                ("DD_TRACE_RATE_LIMIT", "50"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let mut builder = Config::builder_with_sources(&sources);
        builder.set_trace_sampling_rules(vec![SamplingRuleConfig {
            sample_rate: 0.8,
            service: Some("manual-service".to_string()),
            name: None,
            resource: None,
            tags: HashMap::new(),
            provenance: "manual".to_string(),
        }]);
        builder.set_trace_rate_limit(200);
        builder.set_service("manual-service".to_string());
        builder.set_env("manual-env".to_string());
        builder.set_log_level_filter(super::LevelFilter::Warn);

        let config = builder.build();

        assert_eq!(config.trace_rate_limit(), 200);
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            &config.trace_sampling_rules()[0],
            &SamplingRuleConfig {
                sample_rate: 0.8,
                service: Some("manual-service".to_string()),
                provenance: "manual".to_string(),
                ..SamplingRuleConfig::default()
            }
        );

        assert!(config.enabled());
        assert_eq!(config.log_level_filter(), &super::LevelFilter::Warn);
    }

    #[test]
    fn test_propagation_config_from_source() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE", ""),
                (
                    "DD_TRACE_PROPAGATION_STYLE_EXTRACT",
                    "datadog,  tracecontext, invalid",
                ),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "tracecontext"),
                ("DD_TRACE_PROPAGATION_EXTRACT_FIRST", "true"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_propagation_style(), Some(vec![]).as_deref());
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![TracePropagationStyle::TraceContext]).as_deref()
        );
        assert!(config.trace_propagation_extract_first())
    }

    #[test]
    fn test_propagation_config_from_source_override() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE", ""),
                (
                    "DD_TRACE_PROPAGATION_STYLE_EXTRACT",
                    "datadog,  tracecontext",
                ),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "tracecontext"),
                ("DD_TRACE_PROPAGATION_EXTRACT_FIRST", "true"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let mut builder = Config::builder_with_sources(&sources);
        builder.set_trace_propagation_style(vec![
            TracePropagationStyle::TraceContext,
            TracePropagationStyle::Datadog,
        ]);
        builder.set_trace_propagation_style_extract(vec![TracePropagationStyle::TraceContext]);
        builder.set_trace_propagation_style_inject(vec![TracePropagationStyle::Datadog]);
        builder.set_trace_propagation_extract_first(false);

        let config = builder.build();

        assert_eq!(
            config.trace_propagation_style(),
            Some(vec![
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::Datadog
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![TracePropagationStyle::TraceContext]).as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![TracePropagationStyle::Datadog]).as_deref()
        );
        assert!(!config.trace_propagation_extract_first());
    }

    #[test]
    fn test_propagation_config_incorrect_extract() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE", "datadog,  tracecontext"),
                ("DD_TRACE_PROPAGATION_STYLE_EXTRACT", "incorrect,"),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "tracecontext"),
                ("DD_TRACE_PROPAGATION_EXTRACT_FIRST", "true"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(
            config.trace_propagation_style(),
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![]).as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![TracePropagationStyle::TraceContext]).as_deref()
        );
        assert!(config.trace_propagation_extract_first());
    }
    #[test]
    fn test_propagation_config_empty_extract() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE", ""),
                ("DD_TRACE_PROPAGATION_STYLE_EXTRACT", ""),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "tracecontext"),
                ("DD_TRACE_PROPAGATION_EXTRACT_FIRST", "true"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_propagation_style(), Some(vec![]).as_deref());
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![]).as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![TracePropagationStyle::TraceContext]).as_deref()
        );
        assert!(config.trace_propagation_extract_first());
    }

    #[test]
    fn test_propagation_config_not_present_extract() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "tracecontext"),
                ("DD_TRACE_PROPAGATION_EXTRACT_FIRST", "true"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_propagation_style(), None);
        assert_eq!(config.trace_propagation_style_extract(), None);
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![TracePropagationStyle::TraceContext]).as_deref()
        );
        assert!(config.trace_propagation_extract_first());
    }

    #[test]
    fn test_stats_computation_enabled_config() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_STATS_COMPUTATION_ENABLED", "false")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(!config.trace_stats_computation_enabled());

        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_STATS_COMPUTATION_ENABLED", "true")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(config.trace_stats_computation_enabled());

        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_STATS_COMPUTATION_ENABLED", "a")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(config.trace_stats_computation_enabled());

        let mut builder = Config::builder();
        builder.set_trace_stats_computation_enabled(false);
        let config = builder.build();
        assert!(!config.trace_stats_computation_enabled());
    }
}
