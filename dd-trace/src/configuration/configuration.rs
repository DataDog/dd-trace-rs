// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::{borrow::Cow, fmt::Display, str::FromStr, sync::OnceLock};

use crate::dd_warn;
use crate::log::LevelFilter;

use super::sources::{CompositeConfigSourceResult, CompositeSource};

/// Type alias for remote configuration callback functions  
type RemoteConfigCallback = Box<dyn Fn(&[SamplingRuleConfig]) + Send + Sync>;

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

#[derive(Debug, Default, Clone)]
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

/// Source of a configuration value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    #[allow(dead_code)] // Used in tests, returned by source()
    Default,
    EnvVar,
    #[allow(dead_code)] // Will be used when set_code is called from user code
    Code,
    #[allow(dead_code)] // Will be used for remote configuration
    RemoteConfig,
}

/// Configuration item that tracks the value of a setting and where it came from
// This allows us to manage configuration precedence
#[derive(Debug, Clone)]
pub struct ConfigItem<T> {
    name: String,
    default_value: T,
    env_value: Option<T>,
    code_value: Option<T>,
    rc_value: Option<T>,
}

impl<T: Clone> ConfigItem<T> {
    /// Creates a new ConfigItem with a default value
    pub fn new(name: impl Into<String>, default: T) -> Self {
        Self {
            name: name.into(),
            default_value: default,
            env_value: None,
            code_value: None,
            rc_value: None,
        }
    }

    /// Sets a value from a specific source
    pub fn set_value_source(&mut self, value: T, source: ConfigSource) {
        match source {
            ConfigSource::Code => self.code_value = Some(value),
            ConfigSource::RemoteConfig => self.rc_value = Some(value),
            ConfigSource::EnvVar => self.env_value = Some(value),
            ConfigSource::Default => {
                dd_warn!("Cannot set default value after initialization");
            }
        }
    }

    /// Sets the code value (convenience method)
    pub fn set_code(&mut self, value: T) {
        self.code_value = Some(value);
    }

    /// Unsets the remote config value
    #[allow(dead_code)] // Will be used when implementing remote configuration
    pub fn unset_rc(&mut self) {
        self.rc_value = None;
    }

    /// Gets the current value based on priority:
    /// remote_config > code > env_var > default
    pub fn value(&self) -> &T {
        self.rc_value
            .as_ref()
            .or(self.code_value.as_ref())
            .or(self.env_value.as_ref())
            .unwrap_or(&self.default_value)
    }

    /// Gets the source of the current value
    #[allow(dead_code)] // Used in tests and will be used for remote configuration
    pub fn source(&self) -> ConfigSource {
        if self.rc_value.is_some() {
            ConfigSource::RemoteConfig
        } else if self.code_value.is_some() {
            ConfigSource::Code
        } else if self.env_value.is_some() {
            ConfigSource::EnvVar
        } else {
            ConfigSource::Default
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Display for ConfigItem<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<ConfigItem name={} default={:?} env_value={:?} code_value={:?} rc_value={:?}>",
            self.name, self.default_value, self.env_value, self.code_value, self.rc_value
        )
    }
}

type SamplingRulesConfigItem = ConfigItem<ParsedSamplingRules>;

/// Manages extra services discovered at runtime
/// This is used to track services beyond the main service for remote configuration
#[derive(Debug, Clone)]
struct ExtraServicesTracker {
    /// Whether remote configuration is enabled
    remote_config_enabled: bool,
    /// Services that have been discovered
    extra_services: Arc<Mutex<HashSet<String>>>,
    /// Services that have already been sent to the agent
    extra_services_sent: Arc<Mutex<HashSet<String>>>,
    /// Queue of new services to process
    extra_services_queue: Arc<Mutex<Option<VecDeque<String>>>>,
}

impl ExtraServicesTracker {
    fn new(remote_config_enabled: bool) -> Self {
        Self {
            extra_services: Arc::new(Mutex::new(HashSet::new())),
            extra_services_sent: Arc::new(Mutex::new(HashSet::new())),
            extra_services_queue: Arc::new(Mutex::new(Some(VecDeque::new()))),
            remote_config_enabled,
        }
    }

    fn add_extra_service(&self, service_name: &str, main_service: &str) {
        if !self.remote_config_enabled {
            return;
        }

        if service_name == main_service {
            return;
        }

        let mut sent = match self.extra_services_sent.lock() {
            Ok(s) => s,
            Err(_) => return,
        };

        if sent.contains(service_name) {
            return;
        }

        let mut queue = match self.extra_services_queue.lock() {
            Ok(q) => q,
            Err(_) => return,
        };

        // Add to queue and mark as sent
        if let Some(ref mut q) = *queue {
            q.push_back(service_name.to_string());
        }
        sent.insert(service_name.to_string());
    }

    /// Get all extra services, updating from the queue
    fn get_extra_services(&self) -> Vec<String> {
        if !self.remote_config_enabled {
            return Vec::new();
        }

        let mut queue = match self.extra_services_queue.lock() {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };

        let mut services = match self.extra_services.lock() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Drain the queue into extra_services
        if let Some(ref mut q) = *queue {
            while let Some(service) = q.pop_front() {
                services.insert(service);

                // Limit to 64 services
                if services.len() > 64 {
                    // Remove one arbitrary service (HashSet doesn't guarantee order)
                    if let Some(to_remove) = services.iter().next().cloned() {
                        dd_warn!("ExtraServicesTracker:RemoteConfig: Exceeded 64 service limit, removing service: {}", to_remove);
                        services.remove(&to_remove);
                    }
                }
            }
        }

        services.iter().cloned().collect()
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

#[derive(Debug, Clone)]
enum ServiceName {
    Default,
    Configured(String),
}

impl ServiceName {
    fn is_default(&self) -> bool {
        matches!(self, ServiceName::Default)
    }

    fn as_str(&self) -> &str {
        match self {
            ServiceName::Default => "unnamed-rust-service",
            ServiceName::Configured(name) => name,
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
/// Configuration for the Datadog Tracer
///
/// # Usage
/// ```
/// use dd_trace::Config;
///
///
/// let config = Config::builder() // This pulls configuration from the environment and other sources
///     .set_service("my-service".to_string()) // Override service name
///     .set_version("1.0.0".to_string()) // Override version
/// .build();
/// ```
pub struct Config {
    // # Global
    runtime_id: &'static str,

    // # Tracer
    tracer_version: &'static str,
    language_version: &'static str,

    // # Service tagging
    service: ServiceName,
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
    trace_sampling_rules: SamplingRulesConfigItem,

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

    /// Whether remote configuration is enabled
    remote_config_enabled: bool,

    /// Tracks extra services discovered at runtime
    /// Used for remote configuration to report all services
    extra_services_tracker: ExtraServicesTracker,

    /// General callbacks to be called when configuration is updated from remote configuration
    /// Allows components like the DatadogSampler to be updated without circular imports
    remote_config_callbacks: Arc<Mutex<HashMap<String, RemoteConfigCallback>>>,
}

impl Config {
    fn from_sources(sources: &CompositeSource) -> Self {
        let default = default_config();

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

        // Initialize the sampling rules ConfigItem
        let mut sampling_rules_item = ConfigItem::new(
            "DD_TRACE_SAMPLING_RULES",
            ParsedSamplingRules::default(), // default is empty rules
        );

        // Set env value if it was parsed from environment
        if let Some(rules) = parsed_sampling_rules_config {
            sampling_rules_item.set_value_source(rules, ConfigSource::EnvVar);
        }

        // Parse remote configuration enabled flag
        let remote_config_enabled =
            to_val(sources.get_parse::<bool>("DD_REMOTE_CONFIGURATION_ENABLED")).unwrap_or(true); // Default to enabled

        Self {
            runtime_id: default.runtime_id,
            tracer_version: default.tracer_version,
            language_version: default.language_version,
            service: to_val(sources.get("DD_SERVICE"))
                .map(ServiceName::Configured)
                .unwrap_or(default.service),
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

            // Use the initialized ConfigItem
            trace_sampling_rules: sampling_rules_item,
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
            extra_services_tracker: ExtraServicesTracker::new(remote_config_enabled),
            remote_config_enabled,
            remote_config_callbacks: Arc::new(Mutex::new(HashMap::new())),
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
        self.service.as_str()
    }

    pub fn service_is_default(&self) -> bool {
        self.service.is_default()
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
        self.trace_sampling_rules.value().rules.as_ref()
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

    /// Updates sampling rules from remote configuration
    pub fn update_sampling_rules_from_remote(&mut self, rules_json: &str) -> Result<(), String> {
        // Parse the JSON into SamplingRuleConfig objects
        let rules: Vec<SamplingRuleConfig> = serde_json::from_str(rules_json)
            .map_err(|e| format!("Failed to parse sampling rules JSON: {}", e))?;

        let parsed_rules = ParsedSamplingRules { rules };
        self.trace_sampling_rules
            .set_value_source(parsed_rules, ConfigSource::RemoteConfig);

        // Notify the datadog_sampler_on_rules_update callback about the update
        // This specifically calls the DatadogSampler's on_rules_update method
        if let Ok(callbacks) = self.remote_config_callbacks.lock() {
            if let Some(callback) = callbacks.get("datadog_sampler_on_rules_update") {
                callback(self.trace_sampling_rules());
            }
        }

        Ok(())
    }

    /// Clears remote configuration sampling rules, falling back to code/env/default
    pub fn clear_remote_sampling_rules(&mut self) {
        self.trace_sampling_rules.unset_rc();

        // Notify the datadog_sampler_on_rules_update callback about the clearing (pass empty rules)
        // This specifically calls the DatadogSampler's on_rules_update method
        if let Ok(callbacks) = self.remote_config_callbacks.lock() {
            if let Some(callback) = callbacks.get("datadog_sampler_on_rules_update") {
                // Pass empty rules slice
                callback(&[]);
            }
        }
    }

    /// Add a callback to be called when sampling rules are updated from remote configuration
    /// This allows components like the DatadogSampler to be updated without circular imports
    ///
    /// # Arguments
    /// * `key` - A unique identifier for this callback (e.g., "datadog_sampler_on_rules_update")
    /// * `callback` - The function to call when sampling rules are updated (receives
    ///   SamplingRuleConfig slice)
    ///
    /// # Example
    /// ```
    /// use dd_trace::Config;
    /// use std::sync::Arc;
    ///
    /// let config = Config::builder().build();
    /// config.add_remote_config_callback("datadog_sampler_on_rules_update".to_string(), |rules| {
    ///     println!("Received {} new sampling rules", rules.len());
    ///     // Update your sampler here
    /// });
    /// ```
    pub fn add_remote_config_callback<F>(&self, key: String, callback: F)
    where
        F: Fn(&[SamplingRuleConfig]) + Send + Sync + 'static,
    {
        if let Ok(mut callbacks) = self.remote_config_callbacks.lock() {
            callbacks.insert(key, Box::new(callback));
        }
    }

    /// Remove a specific callback by key
    pub fn remove_remote_config_callback(&self, key: &str) {
        if let Ok(mut callbacks) = self.remote_config_callbacks.lock() {
            callbacks.remove(key);
        }
    }

    /// Remove all remote config callbacks
    pub fn clear_remote_config_callbacks(&self) {
        if let Ok(mut callbacks) = self.remote_config_callbacks.lock() {
            callbacks.clear();
        }
    }

    /// Add an extra service discovered at runtime
    /// This is used for remote configuration
    pub fn add_extra_service(&self, service_name: &str) {
        self.extra_services_tracker
            .add_extra_service(service_name, self.service());
    }

    /// Get all extra services discovered at runtime
    pub fn get_extra_services(&self) -> Vec<String> {
        self.extra_services_tracker.get_extra_services()
    }

    /// Check if remote configuration is enabled
    pub fn remote_config_enabled(&self) -> bool {
        self.remote_config_enabled
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("runtime_id", &self.runtime_id)
            .field("tracer_version", &self.tracer_version)
            .field("language_version", &self.language_version)
            .field("service", &self.service)
            .field("env", &self.env)
            .field("version", &self.version)
            .field("global_tags", &self.global_tags)
            .field("trace_agent_url", &self.trace_agent_url)
            .field("dogstatsd_agent_url", &self.dogstatsd_agent_url)
            .field("trace_sampling_rules", &self.trace_sampling_rules)
            .field("trace_rate_limit", &self.trace_rate_limit)
            .field("enabled", &self.enabled)
            .field("log_level_filter", &self.log_level_filter)
            .field(
                "trace_stats_computation_enabled",
                &self.trace_stats_computation_enabled,
            )
            .field("trace_propagation_style", &self.trace_propagation_style)
            .field(
                "trace_propagation_style_extract",
                &self.trace_propagation_style_extract,
            )
            .field(
                "trace_propagation_style_inject",
                &self.trace_propagation_style_inject,
            )
            .field(
                "trace_propagation_extract_first",
                &self.trace_propagation_extract_first,
            )
            .field("extra_services_tracker", &self.extra_services_tracker)
            .field("remote_config_enabled", &self.remote_config_enabled)
            .field("remote_config_callbacks", &"<callbacks>")
            .finish()
    }
}

fn default_config() -> Config {
    Config {
        runtime_id: Config::process_runtime_id(),
        env: None,
        // TODO(paullgdc): Default service naming detection, probably from arg0
        service: ServiceName::Default,
        version: None,
        global_tags: Vec::new(),

        trace_agent_url: Cow::Borrowed("http://localhost:8126"),
        dogstatsd_agent_url: Cow::Borrowed("http://localhost:8125"),
        trace_sampling_rules: ConfigItem::new(
            "DD_TRACE_SAMPLING_RULES",
            ParsedSamplingRules::default(), // Empty rules by default
        ),
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
        extra_services_tracker: ExtraServicesTracker::new(true),
        remote_config_enabled: true,
        remote_config_callbacks: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Finalizes the builder and returns the configuration
    pub fn build(&self) -> Config {
        crate::log::set_max_level(self.config.log_level_filter);
        self.config.clone()
    }

    pub fn set_service(&mut self, service: String) -> &mut Self {
        self.config.service = ServiceName::Configured(service);
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
        // Create a new ParsedSamplingRules and set it as code value
        let parsed_rules = ParsedSamplingRules { rules };
        self.config.trace_sampling_rules.set_code(parsed_rules);
        self
    }

    pub fn set_trace_rate_limit(&mut self, rate_limit: i32) -> &mut Self {
        self.config.trace_rate_limit = rate_limit;
        self
    }

    pub fn set_trace_propagation_style(&mut self, styles: Vec<TracePropagationStyle>) -> &mut Self {
        self.config.trace_propagation_style = Some(styles);
        self
    }

    pub fn set_trace_propagation_style_extract(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config.trace_propagation_style_extract = Some(styles);
        self
    }

    pub fn set_trace_propagation_style_inject(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config.trace_propagation_style_inject = Some(styles);
        self
    }

    pub fn set_trace_propagation_extract_first(&mut self, first: bool) -> &mut Self {
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

    pub fn set_remote_config_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.remote_config_enabled = enabled;
        // Also update the extra services tracker
        self.config.extra_services_tracker = ExtraServicesTracker::new(enabled);
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
        let config = Config::builder_with_sources(&sources)
            .set_trace_sampling_rules(vec![SamplingRuleConfig {
                sample_rate: 0.8,
                service: Some("manual-service".to_string()),
                name: None,
                resource: None,
                tags: HashMap::new(),
                provenance: "manual".to_string(),
            }])
            .set_trace_rate_limit(200)
            .set_service("manual-service".to_string())
            .set_env("manual-env".to_string())
            .set_log_level_filter(super::LevelFilter::Warn)
            .build();

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
        let config = Config::builder_with_sources(&sources)
            .set_trace_propagation_style(vec![
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::Datadog,
            ])
            .set_trace_propagation_style_extract(vec![TracePropagationStyle::TraceContext])
            .set_trace_propagation_style_inject(vec![TracePropagationStyle::Datadog])
            .set_trace_propagation_extract_first(false)
            .build();

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

        let config = Config::builder()
            .set_trace_stats_computation_enabled(false)
            .build();

        assert!(!config.trace_stats_computation_enabled());
    }

    #[test]
    fn test_extra_services_tracking() {
        let config = Config::builder()
            .set_service("main-service".to_string())
            .build();

        // Initially empty
        assert_eq!(config.get_extra_services().len(), 0);

        // Add some extra services
        config.add_extra_service("service-1");
        config.add_extra_service("service-2");
        config.add_extra_service("service-3");

        // Should not add the main service
        config.add_extra_service("main-service");

        // Should not add duplicates
        config.add_extra_service("service-1");

        let services = config.get_extra_services();
        assert_eq!(services.len(), 3);
        assert!(services.contains(&"service-1".to_string()));
        assert!(services.contains(&"service-2".to_string()));
        assert!(services.contains(&"service-3".to_string()));
        assert!(!services.contains(&"main-service".to_string()));
    }

    #[test]
    fn test_extra_services_disabled_when_remote_config_disabled() {
        let config = Config::builder()
            .set_service("main-service".to_string())
            .set_remote_config_enabled(false)
            .build();

        // Add services when remote config is disabled
        config.add_extra_service("service-1");
        config.add_extra_service("service-2");

        // Should return empty since remote config is disabled
        let services = config.get_extra_services();
        assert_eq!(services.len(), 0);
    }

    #[test]
    fn test_extra_services_limit() {
        let config = Config::builder()
            .set_service("main-service".to_string())
            .build();

        // Add more than 64 services
        for i in 0..70 {
            config.add_extra_service(&format!("service-{}", i));
        }

        // Should be limited to 64
        let services = config.get_extra_services();
        assert_eq!(services.len(), 64);
    }

    #[test]
    fn test_remote_config_enabled_from_env() {
        // Test with explicit true
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_REMOTE_CONFIGURATION_ENABLED", "true")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(config.remote_config_enabled());

        // Test with explicit false
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_REMOTE_CONFIGURATION_ENABLED", "false")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(!config.remote_config_enabled());

        // Test with invalid value (should default to true)
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_REMOTE_CONFIGURATION_ENABLED", "invalid")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert!(config.remote_config_enabled());

        // Test without env var (should use default)
        let config = Config::builder().build();
        assert!(config.remote_config_enabled()); // Default is true based on user's change
    }

    #[test]
    fn test_sampling_rules_update_callbacks() {
        let mut config = Config::builder().build();

        // Track callback invocations
        let callback_called = Arc::new(Mutex::new(false));
        let callback_rules = Arc::new(Mutex::new(Vec::<SamplingRuleConfig>::new()));

        let callback_called_clone = callback_called.clone();
        let callback_rules_clone = callback_rules.clone();

        config.add_remote_config_callback(
            "datadog_sampler_on_rules_update".to_string(),
            move |rules| {
                *callback_called_clone.lock().unwrap() = true;
                // Store the rules directly for testing
                *callback_rules_clone.lock().unwrap() = rules.to_vec();
            },
        );

        // Initially callback should not be called
        assert!(!*callback_called.lock().unwrap());
        assert!(callback_rules.lock().unwrap().is_empty());

        // Update rules from remote config
        let new_rules = vec![SamplingRuleConfig {
            sample_rate: 0.5,
            service: Some("test-service".to_string()),
            provenance: "remote".to_string(),
            ..SamplingRuleConfig::default()
        }];

        let rules_json = serde_json::to_string(&new_rules).unwrap();
        config
            .update_sampling_rules_from_remote(&rules_json)
            .unwrap();

        // Callback should be called with the new rules
        assert!(*callback_called.lock().unwrap());
        assert_eq!(*callback_rules.lock().unwrap(), new_rules);

        // Test clearing rules
        *callback_called.lock().unwrap() = false;
        callback_rules.lock().unwrap().clear();

        config.clear_remote_sampling_rules();

        // Callback should be called with empty rules
        assert!(*callback_called.lock().unwrap());
        assert!(callback_rules.lock().unwrap().is_empty());
    }

    #[test]
    fn test_config_item_priority() {
        // Test that ConfigItem respects priority: remote_config > code > env_var > default
        let mut config_item =
            ConfigItem::new("DD_TRACE_SAMPLING_RULES", ParsedSamplingRules::default());

        // Default value
        assert_eq!(config_item.source(), ConfigSource::Default);
        assert_eq!(config_item.value().rules.len(), 0);

        // Env overrides default
        config_item.set_value_source(
            ParsedSamplingRules {
                rules: vec![SamplingRuleConfig {
                    sample_rate: 0.3,
                    ..SamplingRuleConfig::default()
                }],
            },
            ConfigSource::EnvVar,
        );
        assert_eq!(config_item.source(), ConfigSource::EnvVar);
        assert_eq!(config_item.value().rules[0].sample_rate, 0.3);

        // Code overrides env
        config_item.set_code(ParsedSamplingRules {
            rules: vec![SamplingRuleConfig {
                sample_rate: 0.5,
                ..SamplingRuleConfig::default()
            }],
        });
        assert_eq!(config_item.source(), ConfigSource::Code);
        assert_eq!(config_item.value().rules[0].sample_rate, 0.5);

        // Remote config overrides all
        config_item.set_value_source(
            ParsedSamplingRules {
                rules: vec![SamplingRuleConfig {
                    sample_rate: 0.8,
                    ..SamplingRuleConfig::default()
                }],
            },
            ConfigSource::RemoteConfig,
        );
        assert_eq!(config_item.source(), ConfigSource::RemoteConfig);
        assert_eq!(config_item.value().rules[0].sample_rate, 0.8);

        // Unset RC falls back to code
        config_item.unset_rc();
        assert_eq!(config_item.source(), ConfigSource::Code);
        assert_eq!(config_item.value().rules[0].sample_rate, 0.5);
    }

    #[test]
    fn test_sampling_rules_with_config_item() {
        // Test integration: env var is parsed, then overridden by code
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [(
                "DD_TRACE_SAMPLING_RULES",
                r#"[{"sample_rate":0.25,"service":"env-service"}]"#,
            )],
            ConfigSourceOrigin::EnvVar,
        ));

        // First, env var should be used
        let config = Config::builder_with_sources(&sources).build();
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.25);

        // Builder override should take precedence
        let config = Config::builder_with_sources(&sources)
            .set_trace_sampling_rules(vec![SamplingRuleConfig {
                sample_rate: 0.75,
                service: Some("code-service".to_string()),
                ..SamplingRuleConfig::default()
            }])
            .build();
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.75);
        assert_eq!(
            config.trace_sampling_rules()[0].service.as_ref().unwrap(),
            "code-service"
        );
    }
}
