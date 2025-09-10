// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use ddtelemetry::data::Configuration;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::{borrow::Cow, fmt::Display, str::FromStr, sync::OnceLock};

use rustc_version_runtime::version;

use crate::configuration::sources::{
    CompositeConfigSourceResult, CompositeSource, ConfigKey, ConfigSourceOrigin,
};
use crate::log::LevelFilter;
use crate::{dd_error, dd_warn};

/// Different types of remote configuration updates that can trigger callbacks
#[derive(Debug, Clone)]
pub enum RemoteConfigUpdate {
    /// Sampling rules were updated from remote configuration
    SamplingRules(Vec<SamplingRuleConfig>),
    // Future remote config update types should be added here as new variants.
    // E.g.
    // - FeatureFlags(HashMap<String, bool>)
}

/// Type alias for remote configuration callback functions
/// This reduces type complexity and improves readability
type RemoteConfigCallback = Box<dyn Fn(&RemoteConfigUpdate) + Send + Sync>;

/// Struct-based callback system for remote configuration updates
pub struct RemoteConfigCallbacks {
    pub sampling_rules_update: Option<RemoteConfigCallback>,
    // Future callback types can be added here as new fields
    // e.g. pub feature_flags_update: Option<RemoteConfigCallback>,
}

impl std::fmt::Debug for RemoteConfigCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteConfigCallbacks")
            .field(
                "sampling_rules_update",
                &self.sampling_rules_update.as_ref().map(|_| "<callback>"),
            )
            .finish()
    }
}

impl RemoteConfigCallbacks {
    pub fn new() -> Self {
        Self {
            sampling_rules_update: None,
        }
    }

    pub fn set_sampling_rules_callback<F>(&mut self, callback: F)
    where
        F: Fn(&RemoteConfigUpdate) + Send + Sync + 'static,
    {
        self.sampling_rules_update = Some(Box::new(callback));
    }

    /// Calls all relevant callbacks for the given update type
    /// Provides a unified interface for future callback types
    pub fn notify_update(&self, update: &RemoteConfigUpdate) {
        match update {
            RemoteConfigUpdate::SamplingRules(_) => {
                if let Some(ref callback) = self.sampling_rules_update {
                    callback(update);
                }
            } // Future update types can be handled here
        }
    }
}

impl Default for RemoteConfigCallbacks {
    fn default() -> Self {
        Self::new()
    }
}

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

impl Display for SamplingRuleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::json!(self))
    }
}

fn default_provenance() -> String {
    "default".to_string()
}

pub const TRACER_VERSION: &str = "0.0.1";

#[derive(Debug, Default, Clone, PartialEq)]
struct ParsedSamplingRules {
    rules: Vec<SamplingRuleConfig>,
}

impl Deref for ParsedSamplingRules {
    type Target = [SamplingRuleConfig];

    fn deref(&self) -> &Self::Target {
        &self.rules
    }
}

impl From<ParsedSamplingRules> for Vec<SamplingRuleConfig> {
    fn from(parsed: ParsedSamplingRules) -> Self {
        parsed.rules
    }
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

impl Display for ParsedSamplingRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rules = self
            .rules
            .iter()
            .map(|rule| rule.to_string())
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "[{rules}]")
    }
}

enum ConfigItemRef<'a, T> {
    Ref(&'a T),
    ArcRef(arc_swap::Guard<Option<Arc<T>>>),
}

impl<T> Deref for ConfigItemRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            ConfigItemRef::Ref(t) => t,
            ConfigItemRef::ArcRef(guard) => guard.as_ref().unwrap(),
        }
    }
}

/// A trait for converting configuration values to their string representation for telemetry.
///
/// This trait is used to serialize configuration values into strings that can be sent
/// as part of telemetry data to Datadog. It provides a standardized way to convert
/// various configuration types (primitives, enums, collections, etc.) into a string
/// format suitable for the `ddtelemetry::data::payloads::Configuration` payload.
///
/// # Auto-Implementation
///
/// The trait is automatically implemented for common types using the `impl_config_value_provider!`
/// macro:
/// - Basic types: `bool`, `u32`, `i32`, `f64`, `Cow<'static, str>`, etc.
/// - Option wrappers: `Option<String>`, etc.
/// - Custom types: `ServiceName`, `LevelFilter`, `ParsedSamplingRules`, etc.
///
/// # Usage in Configuration System
///
/// This trait is primarily used by `ConfigItem<T>` and `ConfigItemWithOverride<T>`
/// to serialize their current values for telemetry reporting, regardless of the value's source
/// (default, environment variable, programmatic setting, or remote configuration).
trait ConfigurationValueProvider {
    /// Returns the string representation of this configuration value for telemetry reporting.
    ///
    /// This method should produce a concise, human-readable string that represents
    /// the current value in a format suitable for debugging and telemetry analysis.
    fn get_configuration_value(&self) -> String;
}

/// A trait for updating configuration values while tracking their origin source.
///
/// This trait provides a standardized interface for setting configuration values on
/// configuration items while preserving information about where the value came from
/// (environment variables, programmatic code, remote configuration, etc.). This source
/// tracking is essential for implementing proper configuration precedence rules and
/// for telemetry reporting.
trait ValueSourceUpdater<T> {
    /// Updates the configuration value while recording its source origin.
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin);
}

/// Configuration item that tracks the value of a setting and where it came from
/// This allows us to manage configuration precedence
#[derive(Debug)]
struct ConfigItem<T: ConfigurationValueProvider> {
    name: &'static str,
    default_value: T,
    env_value: Option<T>,
    code_value: Option<T>,
}

impl<T: Clone + ConfigurationValueProvider> Clone for ConfigItem<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            default_value: self.default_value.clone(),
            env_value: self.env_value.clone(),
            code_value: self.code_value.clone(),
        }
    }
}

impl<T: Clone + ConfigurationValueProvider> ConfigItem<T> {
    /// Creates a new ConfigItem with a default value
    fn new(name: &'static str, default: T) -> Self {
        Self {
            name,
            default_value: default,
            env_value: None,
            code_value: None,
        }
    }

    /// Sets the code value (convenience method)
    fn set_code(&mut self, value: T) {
        self.code_value = Some(value);
    }

    /// Gets the current value based on priority:
    /// code > env_var > default
    fn value(&self) -> &T {
        self.code_value
            .as_ref()
            .or(self.env_value.as_ref())
            .unwrap_or(&self.default_value)
    }

    /// Gets the source of the current value
    #[allow(dead_code)] // Used in tests and will be used for remote configuration
    fn source(&self) -> ConfigSourceOrigin {
        if self.code_value.is_some() {
            ConfigSourceOrigin::Code
        } else if self.env_value.is_some() {
            ConfigSourceOrigin::EnvVar
        } else {
            ConfigSourceOrigin::Default
        }
    }

    /// Gets a Configuration object used as telemetry payload
    fn get_configuration(&self) -> Configuration {
        Configuration {
            name: self.name.to_string(),
            value: self.value().get_configuration_value(),
            origin: self.source().into(),
            config_id: None,
        }
    }
}

impl<T: ConfigurationValueProvider> ValueSourceUpdater<T> for ConfigItem<T> {
    /// Sets a value from a specific source
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin) {
        match source {
            ConfigSourceOrigin::Code => self.code_value = Some(value),
            ConfigSourceOrigin::EnvVar => self.env_value = Some(value),
            ConfigSourceOrigin::RemoteConfig => {
                dd_warn!("Cannot set a value from RC");
            }
            ConfigSourceOrigin::Default => {
                dd_warn!("Cannot set default value after initialization");
            }
        }
    }
}

/// Configuration item that tracks the value of a setting and where it came from
/// And allows to update the corresponding value with a ConfigSourceOrigin
#[derive(Debug)]
struct ConfigItemWithOverride<T: ConfigurationValueProvider> {
    config_item: ConfigItem<T>,
    override_value: arc_swap::ArcSwapOption<T>,
    source_type: ConfigSourceOrigin,
}

impl<T: Clone + ConfigurationValueProvider> Clone for ConfigItemWithOverride<T> {
    fn clone(&self) -> Self {
        Self {
            config_item: self.config_item.clone(),
            override_value: arc_swap::ArcSwapOption::new(self.override_value.load_full()),
            source_type: self.source_type,
        }
    }
}

impl<T: ConfigurationValueProvider + Clone> ConfigItemWithOverride<T> {
    fn new_code(name: &'static str, default: T) -> Self {
        Self {
            config_item: ConfigItem::new(name, default),
            override_value: arc_swap::ArcSwapOption::const_empty(),
            source_type: ConfigSourceOrigin::Code,
        }
    }

    fn new_rc(name: &'static str, default: T) -> Self {
        Self {
            config_item: ConfigItem::new(name, default),
            override_value: arc_swap::ArcSwapOption::const_empty(),
            source_type: ConfigSourceOrigin::RemoteConfig,
        }
    }

    fn source(&self) -> ConfigSourceOrigin {
        if self.override_value.load().is_some() {
            self.source_type
        } else {
            self.config_item.source()
        }
    }

    /// Replaces override value only if origin matches source_type
    fn set_override_value(&self, value: T, source: ConfigSourceOrigin) {
        if source == self.source_type {
            self.override_value.store(Some(Arc::new(value)));
        }
    }

    /// Unsets the override value
    fn unset_override_value(&self) {
        self.override_value.store(None);
    }

    /// Sets Code value only if source_type is Code
    fn set_code(&mut self, value: T) {
        self.set_value_source(value, ConfigSourceOrigin::Code);
    }

    /// Gets the current value based on priority:
    /// remote_config > code > env_var > default
    fn value(&self) -> ConfigItemRef<'_, T> {
        let override_value = self.override_value.load();
        if override_value.is_some() {
            ConfigItemRef::ArcRef(override_value)
        } else {
            ConfigItemRef::Ref(self.config_item.value())
        }
    }

    /// Gets a Configuration object used as telemetry payload
    fn get_configuration(&self) -> Configuration {
        Configuration {
            name: self.config_item.name.to_string(),
            value: self.value().get_configuration_value(),
            origin: self.source().into(),
            config_id: None,
        }
    }
}

impl<T: Clone + ConfigurationValueProvider> ValueSourceUpdater<T> for ConfigItemWithOverride<T> {
    /// Sets a value from a specific source
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin) {
        if source == self.source_type {
            self.set_override_value(value, source);
        } else {
            self.config_item.set_value_source(value, source);
        }
    }
}

struct ConfigItemSourceUpdater<'a> {
    sources: &'a CompositeSource,
}

impl ConfigItemSourceUpdater<'_> {
    fn apply_result<T, U, V, F>(
        &self,
        item_name: &'static str,
        mut item: V,
        result: CompositeConfigSourceResult<U>,
        transform: F,
    ) -> V
    where
        T: Clone + ConfigurationValueProvider,
        V: ValueSourceUpdater<T>,
        F: FnOnce(U) -> T,
    {
        if !result.errors.is_empty() {
            dd_error!(
                "Configuration: Error parsing property {item_name} - {:?}",
                result.errors
            );
        }

        if let Some(ConfigKey { value, origin }) = result.value {
            item.set_value_source(transform(value), origin);
        }
        item
    }

    /// Updates a ConfigItem from sources with parsed value (no transformation)
    fn update_parsed<T, V>(&self, item_name: &'static str, default: V) -> V
    where
        T: Clone + FromStr + ConfigurationValueProvider,
        T::Err: std::fmt::Display,
        V: ValueSourceUpdater<T>,
    {
        let result = self.sources.get_parse::<T>(item_name);
        self.apply_result(item_name, default, result, |value| value)
    }

    /// Updates a ConfigItem from sources string with transformation
    pub fn update_string<T, V, F>(&self, item_name: &'static str, default: V, transform: F) -> V
    where
        T: Clone + ConfigurationValueProvider,
        V: ValueSourceUpdater<T>,
        F: FnOnce(String) -> T,
    {
        let result = self.sources.get(item_name);
        self.apply_result(item_name, default, result, transform)
    }

    /// Updates a ConfigItem from sources with parsed value and transformation
    pub fn update_parsed_with_transform<T, U, V, F>(
        &self,
        item_name: &'static str,
        default: V,
        transform: F,
    ) -> V
    where
        T: Clone + ConfigurationValueProvider,
        U: FromStr,
        U::Err: std::fmt::Display,
        V: ValueSourceUpdater<T>,
        F: FnOnce(U) -> T,
    {
        let result = self.sources.get_parse::<U>(item_name);
        self.apply_result(item_name, default, result, transform)
    }
}

/// Macro to implement ConfigurationValueProvider trait for types that implement Display
macro_rules! impl_config_value_provider {
  // Handle Option<T> specially
  (option: $($type:ty),* $(,)?) => {
      $(
          impl ConfigurationValueProvider for Option<$type> {
              fn get_configuration_value(&self) -> String {
                  match self {
                      Some(value) => value.to_string(),
                      None => String::new(),
                  }
              }
          }
      )*
  };

  // Handle regular types
  (simple: $($type:ty),* $(,)?) => {
      $(
          impl ConfigurationValueProvider for $type {
              fn get_configuration_value(&self) -> String {
                  self.to_string()
              }
          }
      )*
  };
}

type SamplingRulesConfigItem = ConfigItemWithOverride<ParsedSamplingRules>;

/// Manages extra services discovered at runtime
/// This is used to track services beyond the main service for remote configuration
#[derive(Debug, Clone)]
struct ExtraServicesTracker {
    /// Services that have been discovered
    extra_services: Arc<Mutex<HashSet<String>>>,
    /// Services that have already been sent to the agent
    extra_services_sent: Arc<Mutex<HashSet<String>>>,
    /// Queue of new services to process
    extra_services_queue: Arc<Mutex<Option<VecDeque<String>>>>,
}

impl ExtraServicesTracker {
    fn new() -> Self {
        Self {
            extra_services: Arc::new(Mutex::new(HashSet::new())),
            extra_services_sent: Arc::new(Mutex::new(HashSet::new())),
            extra_services_queue: Arc::new(Mutex::new(Some(VecDeque::new()))),
        }
    }

    fn add_extra_service(&self, service_name: &str, main_service: &str) {
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

impl Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl ConfigurationValueProvider for Vec<(String, String)> {
    fn get_configuration_value(&self) -> String {
        self.iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl ConfigurationValueProvider for Option<Vec<TracePropagationStyle>> {
    fn get_configuration_value(&self) -> String {
        match &self {
            Some(styles) => styles
                .iter()
                .map(|style| style.to_string())
                .collect::<Vec<_>>()
                .join(","),
            None => "".to_string(),
        }
    }
}

impl_config_value_provider!(simple: Cow<'static, str>, bool, u32, i32, f64, ServiceName, LevelFilter, ParsedSamplingRules);
impl_config_value_provider!(option: String);

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
    language_version: String,
    language: &'static str,

    // # Service tagging
    service: ConfigItemWithOverride<ServiceName>,
    env: ConfigItem<Option<String>>,
    version: ConfigItem<Option<String>>,

    // # Agent
    /// A list of default tags to be added to every span
    /// If DD_ENV or DD_VERSION is used, it overrides any env or version tag defined in DD_TAGS
    global_tags: ConfigItem<Vec<(String, String)>>,
    /// host of the trace agent
    agent_host: ConfigItem<Cow<'static, str>>,
    /// port of the trace agent
    trace_agent_port: ConfigItem<u32>,
    /// url of the trace agent
    trace_agent_url: ConfigItem<Cow<'static, str>>,
    /// host of the dogstatsd agent
    dogstatsd_agent_host: ConfigItem<Cow<'static, str>>,
    /// port of the dogstatsd agent
    dogstatsd_agent_port: ConfigItem<u32>,
    /// url of the dogstatsd agent
    dogstatsd_agent_url: ConfigItem<Cow<'static, str>>,

    // # Sampling
    ///  A list of sampling rules. Each rule is matched against the root span of a trace
    /// If a rule matches, the trace is sampled with the associated sample rate.
    trace_sampling_rules: SamplingRulesConfigItem,

    /// Maximum number of spans to sample per second
    /// Only applied if trace_sampling_rules are matched
    trace_rate_limit: ConfigItem<i32>,

    /// Disables the library if this is false
    enabled: ConfigItem<bool>,
    /// The log level filter for the tracer
    log_level_filter: ConfigItem<LevelFilter>,

    /// Whether to enable stats computation for the tracer
    /// Results in dropped spans not being sent to the agent
    trace_stats_computation_enabled: ConfigItem<bool>,

    /// Configurations for testing. Not exposed to customer
    #[cfg(feature = "test-utils")]
    wait_agent_info_ready: bool,

    // # Telemetry configuration
    /// Disables telemetry if false
    telemetry_enabled: ConfigItem<bool>,
    /// Disables telemetry log collection if false.
    telemetry_log_collection_enabled: ConfigItem<bool>,
    /// Interval by which telemetry events are flushed (seconds)
    telemetry_heartbeat_interval: ConfigItem<f64>,

    /// Trace propagation configuration
    trace_propagation_style: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_style_extract: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_style_inject: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_extract_first: ConfigItem<bool>,

    /// Whether remote configuration is enabled
    remote_config_enabled: ConfigItem<bool>,

    /// Tracks extra services discovered at runtime
    /// Used for remote configuration to report all services
    extra_services_tracker: ExtraServicesTracker,

    /// General callbacks to be called when configuration is updated from remote configuration
    /// Allows components like the DatadogSampler to be updated without circular imports
    remote_config_callbacks: Arc<Mutex<RemoteConfigCallbacks>>,
}

impl Config {
    fn from_sources(sources: &CompositeSource) -> Self {
        let default = default_config();

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

        /// Wrapper to parse "," separated key:value tags to vector<(key, value)>
        /// discarding tags without ":" delimiter
        struct DdKeyValueTags(Vec<(String, String)>);

        impl FromStr for DdKeyValueTags {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(DdKeyValueTags(
                    s.split(',')
                        .filter_map(|s| {
                            s.split_once(':')
                                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        })
                        .collect(),
                ))
            }
        }

        let parsed_sampling_rules_config =
            sources.get_parse::<ParsedSamplingRules>("DD_TRACE_SAMPLING_RULES");

        let mut sampling_rules_item = ConfigItemWithOverride::new_rc(
            parsed_sampling_rules_config.name,
            ParsedSamplingRules::default(), // default is empty rules
        );

        // Set env value if it was parsed from environment
        if let Some(rules) = parsed_sampling_rules_config.value {
            sampling_rules_item.set_value_source(rules.value, rules.origin);
        }

        let cisu = ConfigItemSourceUpdater { sources };

        Self {
            runtime_id: default.runtime_id,
            tracer_version: default.tracer_version,
            language_version: default.language_version,
            language: default.language,
            service: cisu.update_string("DD_SERVICE", default.service, ServiceName::Configured),
            env: cisu.update_string("DD_ENV", default.env, Some),
            version: cisu.update_string("DD_VERSION", default.version, Some),
            // TODO(paullgdc): tags should be merged, not replaced
            global_tags: cisu.update_parsed_with_transform(
                "DD_TAGS",
                default.global_tags,
                |DdKeyValueTags(tags)| tags,
            ),
            agent_host: cisu.update_string("DD_AGENT_HOST", default.agent_host, Cow::Owned),
            trace_agent_port: cisu.update_parsed("DD_TRACE_AGENT_PORT", default.trace_agent_port),
            trace_agent_url: cisu.update_string(
                "DD_TRACE_AGENT_URL",
                default.trace_agent_url,
                Cow::Owned,
            ),
            dogstatsd_agent_host: cisu.update_string(
                "DD_DOGSTATSD_HOST",
                default.dogstatsd_agent_host,
                Cow::Owned,
            ),
            dogstatsd_agent_port: cisu
                .update_parsed("DD_DOGSTATSD_PORT", default.dogstatsd_agent_port),
            dogstatsd_agent_url: cisu.update_string(
                "DD_DOGSTATSD_URL",
                default.dogstatsd_agent_url,
                Cow::Owned,
            ),

            // Use the initialized ConfigItem
            trace_sampling_rules: sampling_rules_item,
            trace_rate_limit: cisu.update_parsed("DD_TRACE_RATE_LIMIT", default.trace_rate_limit),

            enabled: cisu.update_parsed("DD_TRACE_ENABLED", default.enabled),
            log_level_filter: cisu.update_parsed("DD_LOG_LEVEL", default.log_level_filter),
            trace_stats_computation_enabled: cisu.update_parsed(
                "DD_TRACE_STATS_COMPUTATION_ENABLED",
                default.trace_stats_computation_enabled,
            ),
            telemetry_enabled: cisu.update_parsed(
                "DD_INSTRUMENTATION_TELEMETRY_ENABLED",
                default.telemetry_enabled,
            ),
            telemetry_log_collection_enabled: cisu.update_parsed(
                "DD_TELEMETRY_LOG_COLLECTION_ENABLED",
                default.telemetry_log_collection_enabled,
            ),
            telemetry_heartbeat_interval: cisu.update_parsed(
                "DD_TELEMETRY_HEARTBEAT_INTERVAL",
                default.telemetry_heartbeat_interval,
            ),
            trace_propagation_style: cisu.update_parsed_with_transform(
                "DD_TRACE_PROPAGATION_STYLE",
                default.trace_propagation_style,
                |DdTags(tags)| TracePropagationStyle::from_tags(Some(tags)),
            ),
            trace_propagation_style_extract: cisu.update_parsed_with_transform(
                "DD_TRACE_PROPAGATION_STYLE_EXTRACT",
                default.trace_propagation_style_extract,
                |DdTags(tags)| TracePropagationStyle::from_tags(Some(tags)),
            ),
            trace_propagation_style_inject: cisu.update_parsed_with_transform(
                "DD_TRACE_PROPAGATION_STYLE_INJECT",
                default.trace_propagation_style_inject,
                |DdTags(tags)| TracePropagationStyle::from_tags(Some(tags)),
            ),
            trace_propagation_extract_first: cisu.update_parsed(
                "DD_TRACE_PROPAGATION_EXTRACT_FIRST",
                default.trace_propagation_extract_first,
            ),
            #[cfg(feature = "test-utils")]
            wait_agent_info_ready: default.wait_agent_info_ready,
            extra_services_tracker: ExtraServicesTracker::new(),
            remote_config_enabled: cisu.update_parsed(
                "DD_REMOTE_CONFIGURATION_ENABLED",
                default.remote_config_enabled,
            ),
            remote_config_callbacks: Arc::new(Mutex::new(RemoteConfigCallbacks::new())),
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

    pub fn get_config_items(&self) -> Vec<Configuration> {
        vec![
            self.service.get_configuration(),
            self.env.get_configuration(),
            self.version.get_configuration(),
            self.global_tags.get_configuration(),
            self.agent_host.get_configuration(),
            self.trace_agent_port.get_configuration(),
            self.trace_agent_url.get_configuration(),
            self.dogstatsd_agent_host.get_configuration(),
            self.dogstatsd_agent_port.get_configuration(),
            self.dogstatsd_agent_url.get_configuration(),
            self.trace_sampling_rules.get_configuration(),
            self.trace_rate_limit.get_configuration(),
            self.enabled.get_configuration(),
            self.log_level_filter.get_configuration(),
            self.trace_stats_computation_enabled.get_configuration(),
            self.telemetry_enabled.get_configuration(),
            self.telemetry_log_collection_enabled.get_configuration(),
            self.telemetry_heartbeat_interval.get_configuration(),
            self.trace_propagation_style.get_configuration(),
            self.trace_propagation_style_extract.get_configuration(),
            self.trace_propagation_style_inject.get_configuration(),
            self.trace_propagation_extract_first.get_configuration(),
            self.remote_config_enabled.get_configuration(),
        ]
    }

    pub fn runtime_id(&self) -> &str {
        self.runtime_id
    }

    pub fn tracer_version(&self) -> &str {
        self.tracer_version
    }

    pub fn language(&self) -> &str {
        self.language
    }

    pub fn language_version(&self) -> &str {
        self.language_version.as_str()
    }

    pub fn service(&self) -> String {
        self.service.value().to_string()
    }

    pub fn service_is_default(&self) -> bool {
        self.service.value().is_default()
    }

    pub fn env(&self) -> Option<&str> {
        self.env.value().as_deref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.value().as_deref()
    }

    pub fn global_tags(&self) -> impl Iterator<Item = (&str, &str)> {
        self.global_tags
            .value()
            .iter()
            .map(|tag| (tag.0.as_str(), tag.1.as_str()))
    }

    pub fn trace_agent_url(&self) -> &Cow<'static, str> {
        self.trace_agent_url.value()
    }

    pub fn dogstatsd_agent_host(&self) -> &Cow<'static, str> {
        self.dogstatsd_agent_host.value()
    }

    pub fn dogstatsd_agent_port(&self) -> &u32 {
        self.dogstatsd_agent_port.value()
    }

    pub fn dogstatsd_agent_url(&self) -> &Cow<'static, str> {
        self.dogstatsd_agent_url.value()
    }

    pub fn trace_sampling_rules(&self) -> impl Deref<Target = [SamplingRuleConfig]> + use<'_> {
        self.trace_sampling_rules.value().to_vec()
    }

    pub fn trace_rate_limit(&self) -> i32 {
        *self.trace_rate_limit.value()
    }

    pub fn enabled(&self) -> bool {
        *self.enabled.value()
    }

    pub fn log_level_filter(&self) -> &LevelFilter {
        self.log_level_filter.value()
    }

    pub fn trace_stats_computation_enabled(&self) -> bool {
        *self.trace_stats_computation_enabled.value()
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

    pub fn telemetry_enabled(&self) -> bool {
        *self.telemetry_enabled.value()
    }

    pub fn telemetry_log_collection_enabled(&self) -> bool {
        *self.telemetry_log_collection_enabled.value()
    }

    pub fn telemetry_heartbeat_interval(&self) -> f64 {
        *self.telemetry_heartbeat_interval.value()
    }

    pub fn trace_propagation_style(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style.value().as_deref()
    }

    pub fn trace_propagation_style_extract(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_extract.value().as_deref()
    }

    pub fn trace_propagation_style_inject(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_inject.value().as_deref()
    }

    pub fn trace_propagation_extract_first(&self) -> bool {
        *self.trace_propagation_extract_first.value()
    }

    pub fn update_sampling_rules_from_remote(&self, rules_json: &str) -> Result<(), String> {
        // Parse the JSON into SamplingRuleConfig objects
        let rules: Vec<SamplingRuleConfig> = serde_json::from_str(rules_json)
            .map_err(|e| format!("Failed to parse sampling rules JSON: {e}"))?;

        // If remote config sends empty rules, clear remote config to fall back to local rules
        if rules.is_empty() {
            self.clear_remote_sampling_rules();
        } else {
            self.trace_sampling_rules.set_override_value(
                ParsedSamplingRules { rules },
                ConfigSourceOrigin::RemoteConfig,
            );

            // Notify callbacks about the sampling rules update
            self.remote_config_callbacks.lock().unwrap().notify_update(
                &RemoteConfigUpdate::SamplingRules(self.trace_sampling_rules().to_vec()),
            );
        }

        Ok(())
    }

    pub fn update_service_name(&self, service_name: Option<String>) {
        if let Some(service_name) = service_name {
            self.service.set_override_value(
                ServiceName::Configured(service_name),
                ConfigSourceOrigin::Code,
            );
        }
    }

    pub fn clear_remote_sampling_rules(&self) {
        self.trace_sampling_rules.unset_override_value();

        self.remote_config_callbacks.lock().unwrap().notify_update(
            &RemoteConfigUpdate::SamplingRules(self.trace_sampling_rules().to_vec()),
        );
    }

    /// Add a callback to be called when sampling rules are updated via remote configuration
    /// This allows components like DatadogSampler to be updated without circular imports
    ///
    /// # Arguments
    /// * `callback` - The function to call when sampling rules are updated (receives
    ///   RemoteConfigUpdate enum)
    ///
    /// # Example
    /// ```
    /// use dd_trace::{configuration::RemoteConfigUpdate, Config};
    ///
    /// let config = Config::builder().build();
    /// config.set_sampling_rules_callback(|update| {
    ///     match update {
    ///         RemoteConfigUpdate::SamplingRules(rules) => {
    ///             println!("Received {} new sampling rules", rules.len());
    ///             // Update your sampler here
    ///         }
    ///     }
    /// });
    /// ```
    pub fn set_sampling_rules_callback<F>(&self, callback: F)
    where
        F: Fn(&RemoteConfigUpdate) + Send + Sync + 'static,
    {
        self.remote_config_callbacks
            .lock()
            .unwrap()
            .set_sampling_rules_callback(callback);
    }

    /// Add an extra service discovered at runtime
    /// This is used for remote configuration
    pub fn add_extra_service(&self, service_name: &str) {
        if !self.remote_config_enabled() {
            return;
        }
        self.extra_services_tracker
            .add_extra_service(service_name, &self.service());
    }

    /// Get all extra services discovered at runtime
    pub fn get_extra_services(&self) -> Vec<String> {
        if !self.remote_config_enabled() {
            return Vec::new();
        }
        self.extra_services_tracker.get_extra_services()
    }

    /// Check if remote configuration is enabled
    pub fn remote_config_enabled(&self) -> bool {
        *self.remote_config_enabled.value()
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
            .field("remote_config_callbacks", &self.remote_config_callbacks)
            .finish()
    }
}

fn default_config() -> Config {
    Config {
        runtime_id: Config::process_runtime_id(),
        env: ConfigItem::new("DD_ENV", None),
        // TODO(paullgdc): Default service naming detection, probably from arg0
        service: ConfigItemWithOverride::new_code("DD_SERVICE", ServiceName::Default),
        version: ConfigItem::new("DD_VERSION", None),
        global_tags: ConfigItem::new("DD_TAGS", Vec::new()),

        agent_host: ConfigItem::new("DD_AGENT_HOST", Cow::Borrowed("localhost")),
        trace_agent_port: ConfigItem::new("DD_TRACE_AGENT_PORT", 8126),
        trace_agent_url: ConfigItem::new("DD_TRACE_AGENT_URL", Cow::Borrowed("")),
        dogstatsd_agent_host: ConfigItem::new("DD_DOGSTATSD_HOST", Cow::Borrowed("localhost")),
        dogstatsd_agent_port: ConfigItem::new("DD_DOGSTATSD_PORT", 8125),
        dogstatsd_agent_url: ConfigItem::new("DD_DOGSTATSD_URL", Cow::Borrowed("")),
        trace_sampling_rules: ConfigItemWithOverride::new_rc(
            "DD_TRACE_SAMPLING_RULES",
            ParsedSamplingRules::default(), // Empty rules by default
        ),
        trace_rate_limit: ConfigItem::new("DD_TRACE_RATE_LIMIT", 100),
        enabled: ConfigItem::new("DD_TRACE_ENABLED", true),
        log_level_filter: ConfigItem::new("DD_LOG_LEVEL", LevelFilter::default()),
        tracer_version: TRACER_VERSION,
        language: "rust",
        language_version: version().to_string(),
        trace_stats_computation_enabled: ConfigItem::new(
            "DD_TRACE_STATS_COMPUTATION_ENABLED",
            true,
        ),
        #[cfg(feature = "test-utils")]
        wait_agent_info_ready: false,

        telemetry_enabled: ConfigItem::new("DD_INSTRUMENTATION_TELEMETRY_ENABLED", true),
        telemetry_log_collection_enabled: ConfigItem::new(
            "DD_TELEMETRY_LOG_COLLECTION_ENABLED",
            true,
        ),
        telemetry_heartbeat_interval: ConfigItem::new("DD_TELEMETRY_HEARTBEAT_INTERVAL", 60.0),

        trace_propagation_style: ConfigItem::new(
            "DD_TRACE_PROPAGATION_STYLE",
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ]),
        ),
        trace_propagation_style_extract: ConfigItem::new(
            "DD_TRACE_PROPAGATION_STYLE_EXTRACT",
            None,
        ),
        trace_propagation_style_inject: ConfigItem::new("DD_TRACE_PROPAGATION_STYLE_INJECT", None),
        trace_propagation_extract_first: ConfigItem::new(
            "DD_TRACE_PROPAGATION_EXTRACT_FIRST",
            false,
        ),
        extra_services_tracker: ExtraServicesTracker::new(),
        remote_config_enabled: ConfigItem::new("DD_REMOTE_CONFIG_ENABLED", true),
        remote_config_callbacks: Arc::new(Mutex::new(RemoteConfigCallbacks::new())),
    }
}

pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Finalizes the builder and returns the configuration
    pub fn build(&self) -> Config {
        crate::log::set_max_level(*self.config.log_level_filter.value());
        let mut config = self.config.clone();

        // resolve trace_agent_url
        if config.trace_agent_url.value().is_empty() {
            let host = &config.agent_host.value();
            let port = *config.trace_agent_port.value();
            config
                .trace_agent_url
                .set_code(Cow::Owned(format!("http://{host}:{port}")));
        }

        // resolve dogstatsd_agent_url
        if config.dogstatsd_agent_url.value().is_empty() {
            let host = &config.dogstatsd_agent_host.value();
            let port = *config.dogstatsd_agent_port.value();
            config
                .dogstatsd_agent_url
                .set_code(Cow::Owned(format!("http://{host}:{port}")));
        }

        config
    }

    pub fn set_service(&mut self, service: String) -> &mut Self {
        self.config
            .service
            .set_code(ServiceName::Configured(service));
        self
    }

    pub fn set_env(&mut self, env: String) -> &mut Self {
        self.config.env.set_code(Some(env));
        self
    }

    pub fn set_version(&mut self, version: String) -> &mut Self {
        self.config.version.set_code(Some(version));
        self
    }

    pub fn set_global_tags(&mut self, tags: Vec<(String, String)>) -> &mut Self {
        self.config.global_tags.set_code(tags);
        self
    }

    pub fn add_global_tag(&mut self, tag: (String, String)) -> &mut Self {
        let mut current_tags = self.config.global_tags.value().clone();
        current_tags.push(tag);
        self.config.global_tags.set_code(current_tags);
        self
    }

    pub fn set_telemetry_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.telemetry_enabled.set_code(enabled);
        self
    }

    pub fn set_telemetry_log_collection_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config
            .telemetry_log_collection_enabled
            .set_code(enabled);
        self
    }

    pub fn set_telemetry_heartbeat_interval(&mut self, seconds: f64) -> &mut Self {
        self.config.telemetry_heartbeat_interval.set_code(seconds);
        self
    }

    pub fn set_agent_host(&mut self, host: Cow<'static, str>) -> &mut Self {
        self.config
            .agent_host
            .set_code(Cow::Owned(host.to_string()));
        self
    }

    pub fn set_trace_agent_port(&mut self, port: u32) -> &mut Self {
        self.config.trace_agent_port.set_code(port);
        self
    }

    pub fn set_trace_agent_url(&mut self, url: Cow<'static, str>) -> &mut Self {
        self.config
            .trace_agent_url
            .set_code(Cow::Owned(url.to_string()));
        self
    }

    pub fn set_dogstatsd_agent_host(&mut self, host: Cow<'static, str>) -> &mut Self {
        self.config
            .dogstatsd_agent_host
            .set_code(Cow::Owned(host.to_string()));
        self
    }

    pub fn set_dogstatsd_agent_port(&mut self, port: u32) -> &mut Self {
        self.config.dogstatsd_agent_port.set_code(port);
        self
    }

    pub fn set_trace_sampling_rules(&mut self, rules: Vec<SamplingRuleConfig>) -> &mut Self {
        self.config
            .trace_sampling_rules
            .set_code(ParsedSamplingRules { rules });
        self
    }

    pub fn set_trace_rate_limit(&mut self, rate_limit: i32) -> &mut Self {
        self.config.trace_rate_limit.set_code(rate_limit);
        self
    }

    pub fn set_trace_propagation_style(&mut self, styles: Vec<TracePropagationStyle>) -> &mut Self {
        self.config.trace_propagation_style.set_code(Some(styles));
        self
    }

    pub fn set_trace_propagation_style_extract(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config
            .trace_propagation_style_extract
            .set_code(Some(styles));
        self
    }

    pub fn set_trace_propagation_style_inject(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config
            .trace_propagation_style_inject
            .set_code(Some(styles));
        self
    }

    pub fn set_trace_propagation_extract_first(&mut self, first: bool) -> &mut Self {
        self.config.trace_propagation_extract_first.set_code(first);
        self
    }

    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.enabled.set_code(enabled);
        self
    }

    pub fn set_log_level_filter(&mut self, filter: LevelFilter) -> &mut Self {
        self.config.log_level_filter.set_code(filter);
        self
    }

    pub fn set_trace_stats_computation_enabled(
        &mut self,
        trace_stats_computation_enabled: bool,
    ) -> &mut Self {
        self.config
            .trace_stats_computation_enabled
            .set_code(trace_stats_computation_enabled);
        self
    }

    pub fn set_remote_config_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.remote_config_enabled.set_code(enabled);
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
    use ddtelemetry::data::ConfigurationOrigin;

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
        assert_eq!(*config.log_level_filter(), super::LevelFilter::Debug);
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
        assert_eq!(*config.log_level_filter(), super::LevelFilter::Warn);
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

        assert_eq!(
            config.trace_propagation_style(),
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
            ])
            .as_deref()
        );
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
        // Use environment variable to disable remote config
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_REMOTE_CONFIGURATION_ENABLED", "false")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources)
            .set_service("main-service".to_string())
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
            config.add_extra_service(&format!("service-{i}"));
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
        let config = Config::builder().build();

        // Track callback invocations
        let callback_called = Arc::new(Mutex::new(false));
        let callback_rules = Arc::new(Mutex::new(Vec::<SamplingRuleConfig>::new()));

        let callback_called_clone = callback_called.clone();
        let callback_rules_clone = callback_rules.clone();

        config.set_sampling_rules_callback(move |update| {
            *callback_called_clone.lock().unwrap() = true;
            // Store the rules - for now we only have SamplingRules variant
            let RemoteConfigUpdate::SamplingRules(rules) = update;
            *callback_rules_clone.lock().unwrap() = rules.clone();
        });

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

        // Callback should be called with fallback rules (empty in this case since no env/code rules
        // set)
        assert!(*callback_called.lock().unwrap());
        assert!(callback_rules.lock().unwrap().is_empty());
    }

    #[test]
    fn test_config_item_priority() {
        // Test that ConfigItem respects priority: remote_config > code > env_var > default
        let mut config_item = ConfigItemWithOverride::new_rc(
            "DD_TRACE_SAMPLING_RULES",
            ParsedSamplingRules::default(),
        );

        // Default value
        assert_eq!(config_item.source(), ConfigSourceOrigin::Default);
        assert_eq!(config_item.value().len(), 0);

        // Env overrides default
        config_item.set_value_source(
            ParsedSamplingRules {
                rules: vec![SamplingRuleConfig {
                    sample_rate: 0.3,
                    ..SamplingRuleConfig::default()
                }],
            },
            ConfigSourceOrigin::EnvVar,
        );
        assert_eq!(config_item.source(), ConfigSourceOrigin::EnvVar);
        assert_eq!(config_item.value()[0].sample_rate, 0.3);

        // Code overrides env
        config_item.set_code(ParsedSamplingRules {
            rules: vec![SamplingRuleConfig {
                sample_rate: 0.5,
                ..SamplingRuleConfig::default()
            }],
        });
        assert_eq!(config_item.source(), ConfigSourceOrigin::Code);
        assert_eq!(config_item.value()[0].sample_rate, 0.5);

        // Remote config overrides all
        config_item.set_value_source(
            ParsedSamplingRules {
                rules: vec![SamplingRuleConfig {
                    sample_rate: 0.8,
                    ..SamplingRuleConfig::default()
                }],
            },
            ConfigSourceOrigin::RemoteConfig,
        );
        assert_eq!(config_item.source(), ConfigSourceOrigin::RemoteConfig);
        assert_eq!(config_item.value()[0].sample_rate, 0.8);

        // Unset RC falls back to code
        config_item.unset_override_value();
        assert_eq!(config_item.source(), ConfigSourceOrigin::Code);
        assert_eq!(config_item.value()[0].sample_rate, 0.5);
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

        // Code override should take precedence
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

    #[test]
    fn test_empty_remote_rules_fallback_behavior() {
        let mut config = Config::builder().build();

        // 1. Set up local rules via environment variable simulation
        let local_rules = ParsedSamplingRules {
            rules: vec![SamplingRuleConfig {
                sample_rate: 0.3,
                service: Some("local-service".to_string()),
                provenance: "local".to_string(),
                ..SamplingRuleConfig::default()
            }],
        };
        config
            .trace_sampling_rules
            .set_value_source(local_rules.clone(), ConfigSourceOrigin::EnvVar);

        // Verify local rules are active
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.3);
        assert_eq!(
            config.trace_sampling_rules.source(),
            ConfigSourceOrigin::EnvVar
        );

        // 2. Remote config sends non-empty rules
        let remote_rules_json =
            r#"[{"sample_rate": 0.8, "service": "remote-service", "provenance": "remote"}]"#;
        config
            .update_sampling_rules_from_remote(remote_rules_json)
            .unwrap();

        // Verify remote rules override local rules
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.8);
        assert_eq!(
            config.trace_sampling_rules.source(),
            ConfigSourceOrigin::RemoteConfig
        );

        // 3. Remote config sends empty array []
        let empty_remote_rules_json = "[]";
        config
            .update_sampling_rules_from_remote(empty_remote_rules_json)
            .unwrap();

        // Empty remote rules automatically fall back to local rules
        assert_eq!(config.trace_sampling_rules().len(), 1); // Falls back to local rules
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.3); // Local rule values
        assert_eq!(
            config.trace_sampling_rules.source(),
            ConfigSourceOrigin::EnvVar
        ); // Back to env source!

        // 4. Verify explicit clearing still works (for completeness)
        // Since we're already on local rules, clear should keep us on local rules
        config.clear_remote_sampling_rules();

        // Should remain on local rules
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.3);
        assert_eq!(
            config.trace_sampling_rules.source(),
            ConfigSourceOrigin::EnvVar
        );
    }

    #[test]
    fn test_telemetry_config_from_sources() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false"),
                ("DD_TELEMETRY_LOG_COLLECTION_ENABLED", "false"),
                ("DD_TELEMETRY_HEARTBEAT_INTERVAL", "42"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert!(!config.telemetry_enabled());
        assert!(!config.telemetry_log_collection_enabled());
        assert_eq!(config.telemetry_heartbeat_interval(), 42.0);
    }

    #[test]
    fn test_telemetry_config() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false"),
                ("DD_TELEMETRY_LOG_COLLECTION_ENABLED", "false"),
                ("DD_TELEMETRY_HEARTBEAT_INTERVAL", "42"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let mut builder = Config::builder_with_sources(&sources);

        builder
            .set_telemetry_enabled(true)
            .set_telemetry_log_collection_enabled(true)
            .set_telemetry_heartbeat_interval(0.1);

        let config = builder.build();

        assert!(config.telemetry_enabled());
        assert!(config.telemetry_log_collection_enabled());
        assert_eq!(config.telemetry_heartbeat_interval(), 0.1);
    }

    #[test]
    fn test_dd_tags() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TAGS", "key1   :value1          ,   key2:,key3")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        let tags: Vec<(&str, &str)> = config.global_tags().collect();

        assert_eq!(tags.len(), 2);
        assert_eq!(tags, vec![("key1", "value1"), ("key2", "")]);
    }

    #[test]
    fn test_dd_agent_url_default() {
        let config = Config::builder().build();

        assert_eq!(config.trace_agent_url(), "http://localhost:8126");
    }

    #[test]
    fn test_dd_agent_url_from_host_and_port() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_AGENT_HOST", "agent-host"),
                ("DD_TRACE_AGENT_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_url() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_AGENT_URL", "https://test-host"),
                ("DD_AGENT_HOST", "agent-host"),
                ("DD_TRACE_AGENT_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_agent_url(), "https://test-host");
    }

    #[test]
    fn test_dd_agent_url_from_url_empty() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_AGENT_URL", ""),
                ("DD_AGENT_HOST", "agent-host"),
                ("DD_TRACE_AGENT_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_host_and_port_using_builder() {
        let config = Config::builder()
            .set_agent_host("agent-host".into())
            .set_trace_agent_port(4242)
            .build();

        assert_eq!(config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_url_using_builder() {
        let config = Config::builder()
            .set_agent_host("agent-host".into())
            .set_trace_agent_port(4242)
            .set_trace_agent_url("https://test-host".into())
            .build();

        assert_eq!(config.trace_agent_url(), "https://test-host");
    }

    #[test]
    fn test_dogstatsd_agent_url_default() {
        let config = Config::builder().build();

        assert_eq!(config.dogstatsd_agent_url(), "http://localhost:8125");
    }

    #[test]
    fn test_dogstatsd_agent_url_from_host_and_port() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_DOGSTATSD_HOST", "dogstatsd-host"),
                ("DD_DOGSTATSD_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(config.dogstatsd_agent_url(), "http://dogstatsd-host:4242");
    }

    #[test]
    fn test_dogstatsd_agent_url_from_url_using_builder() {
        let config = Config::builder()
            .set_dogstatsd_agent_host("dogstatsd-host".into())
            .set_dogstatsd_agent_port(4242)
            .build();

        assert_eq!(config.dogstatsd_agent_url(), "http://dogstatsd-host:4242");
    }

    #[test]
    fn test_config_source_updater() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_ENV", "test-env")],
            ConfigSourceOrigin::EnvVar,
        ));
        sources.add_source(HashMapSource::from_iter(
            [("DD_ENABLED", "false")],
            ConfigSourceOrigin::RemoteConfig,
        ));
        sources.add_source(HashMapSource::from_iter(
            [("DD_TAGS", "v1,v2")],
            ConfigSourceOrigin::Code,
        ));
        let default = default_config();

        let cisu = ConfigItemSourceUpdater { sources: &sources };

        assert_eq!(default.env(), None);
        assert!(default.enabled());
        assert_eq!(default.global_tags().collect::<Vec<_>>(), vec![]);

        let env = cisu.update_string("DD_ENV", default.env, Some);
        assert_eq!(env.default_value, None);
        assert_eq!(env.env_value, Some(Some("test-env".to_string())));
        assert_eq!(env.code_value, None);

        let enabled = cisu.update_parsed("DD_ENABLED", default.enabled);
        assert!(enabled.default_value);
        assert_eq!(enabled.env_value, None);
        assert_eq!(enabled.code_value, None);

        struct Tags(Vec<(String, String)>);

        impl FromStr for Tags {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Tags(
                    s.split(',')
                        .enumerate()
                        .map(|(index, s)| (index.to_string(), s.to_string()))
                        .collect(),
                ))
            }
        }

        let tags =
            cisu.update_parsed_with_transform("DD_TAGS", default.global_tags, |Tags(tags)| tags);
        assert_eq!(tags.default_value, vec![]);
        assert_eq!(tags.env_value, None);
        assert_eq!(
            tags.code_value,
            Some(vec![
                ("0".to_string(), "v1".to_string()),
                ("1".to_string(), "v2".to_string())
            ])
        );
    }

    #[test]
    fn test_get_configuration_config_item_rc() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_SAMPLING_RULES", 
                 r#"[{"sample_rate":0.5,"service":"web-api","name":null,"resource":null,"tags":{},"provenance":"customer"}]"#),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        let expected = ParsedSamplingRules::from_str(
            r#"[{"sample_rate":0.5,"service":"web-api","name":null,"resource":null,"tags":{},"provenance":"customer"}]"#
        ).unwrap();

        let configuration = &config.trace_sampling_rules.get_configuration();
        assert_eq!(configuration.origin, ConfigurationOrigin::EnvVar);

        // Converting configuration value to json helps with comparison as serialized properties may
        // differ from their original order
        assert_eq!(
            ParsedSamplingRules::from_str(&configuration.value).unwrap(),
            expected.clone()
        );

        // Update ConfigItemRc via RC
        let expected_rc = ParsedSamplingRules::from_str(r#"[{"sample_rate":1,"service":"web-api","name":null,"resource":null,"tags":{},"provenance":"customer"}]"#).unwrap();
        config
            .trace_sampling_rules
            .set_override_value(expected_rc.clone(), ConfigSourceOrigin::RemoteConfig);

        let configuration_after_rc = &config.trace_sampling_rules.get_configuration();
        assert_eq!(
            configuration_after_rc.origin,
            ConfigurationOrigin::RemoteConfig
        );
        assert_eq!(
            ParsedSamplingRules::from_str(&configuration_after_rc.value).unwrap(),
            expected_rc
        );

        // Reset ConfigItemRc RC previous value
        config.trace_sampling_rules.unset_override_value();

        let configuration = &config.trace_sampling_rules.get_configuration();
        assert_eq!(configuration.origin, ConfigurationOrigin::EnvVar);
        assert_eq!(
            ParsedSamplingRules::from_str(&configuration.value).unwrap(),
            expected
        );
    }
}
