// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use libdd_telemetry::data::Configuration;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Display;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{borrow::Cow, sync::OnceLock};

#[cfg(target_os = "linux")]
use libdd_library_config::tracer_metadata::TracerMetadata;

use rustc_version_runtime::version;

use super::{ParsedSamplingRules, SamplingRuleConfig};
use crate::core::configuration::sources::{
    CompositeConfigSourceResult, CompositeSource, ConfigKey, ConfigSourceOrigin,
};
use crate::core::configuration::supported_configurations::SupportedConfigurations;
use crate::core::log::LevelFilter;
use crate::core::telemetry;
use crate::{dd_error, dd_warn};

/// Different types of remote configuration updates that can trigger callbacks
#[derive(Debug, Clone)]
pub enum RemoteConfigUpdate {
    /// Sampling rules were updated from remote configuration.
    /// Uses the internal type to preserve provenance from remote config.
    SamplingRules(Vec<libdd_sampling::SamplingRuleConfig>),
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
pub const TRACER_VERSION: &str = env!("CARGO_PKG_VERSION");

const DATADOG_TAGS_MAX_LENGTH: usize = 512;
const RC_DEFAULT_POLL_INTERVAL: f64 = 5.0; // 5 seconds is the highest interval allowed by the spec
const DEFAULT_UNIX_TRACE_AGENT_URL: &str = "/var/run/datadog/apm.socket";
const DEFAULT_UNIX_DOGSTATSD_AGENT_URL: &str = "/var/run/datadog/dsd.socket";

/// OTLP protocol types for OTLP export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtlpProtocol {
    /// gRPC protocol
    Grpc,
    /// HTTP with protobuf encoding
    HttpProtobuf,
    /// HTTP with JSON encoding
    HttpJson,
}

impl FromStr for OtlpProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("grpc") {
            Ok(OtlpProtocol::Grpc)
        } else if s.eq_ignore_ascii_case("http/protobuf") {
            Ok(OtlpProtocol::HttpProtobuf)
        } else if s.eq_ignore_ascii_case("http/json") {
            Ok(OtlpProtocol::HttpJson)
        } else {
            Err(format!("Invalid OTLP protocol: {}", s))
        }
    }
}

impl OtlpProtocol {
    /// Parse a protocol string, returning None for empty strings
    pub(crate) fn parse_optional(s: String) -> Option<Self> {
        if s.trim().is_empty() {
            None
        } else {
            s.parse().ok()
        }
    }
}

/// Parse a temporality preference string to Temporality enum
fn parse_temporality(s: String) -> Option<opentelemetry_sdk::metrics::Temporality> {
    let s = s.trim().to_lowercase();
    if s == "cumulative" {
        Some(opentelemetry_sdk::metrics::Temporality::Cumulative)
    } else if s == "delta" || s.is_empty() {
        Some(opentelemetry_sdk::metrics::Temporality::Delta)
    } else {
        None
    }
}

/// Validates a global trace sample rate (`DD_TRACE_SAMPLE_RATE`). Returns
/// `Some(rate)` only for finite values in `[0.0, 1.0]`; logs and returns `None`
/// otherwise so the rate is treated as unset rather than installed as a
/// catch-all rule that libdd-sampling would clamp (a negative value would drop
/// all unmatched traffic, a value > 1.0 would keep all of it). Mirrors the
/// range check applied to RC's `tracing_sampling_rate`.
fn validate_trace_sample_rate(rate: f64) -> Option<f64> {
    if rate.is_finite() && (0.0..=1.0).contains(&rate) {
        Some(rate)
    } else {
        crate::dd_warn!(
            "DD_TRACE_SAMPLE_RATE must be in [0.0, 1.0], got {rate}; treating as unset"
        );
        None
    }
}

enum ConfigItemRef<'a, T> {
    Ref(&'a T),
    ArcRef(arc_swap::Guard<Option<Arc<T>>>),
}

impl<T: Deref> Deref for ConfigItemRef<'_, T> {
    type Target = T::Target;

    fn deref(&self) -> &Self::Target {
        match self {
            ConfigItemRef::Ref(t) => t,
            ConfigItemRef::ArcRef(guard) => guard.as_ref().unwrap(),
        }
    }
}

impl<T: ConfigurationValueProvider> ConfigurationValueProvider for ConfigItemRef<'_, T> {
    fn get_configuration_value(&self) -> String {
        match self {
            ConfigItemRef::Ref(t) => t.get_configuration_value(),
            ConfigItemRef::ArcRef(guard) => guard.as_ref().unwrap().get_configuration_value(),
        }
    }
}

/// A trait for providing configuration data for telemetry reporting.
///
/// This trait standardizes how configuration items expose their current state
/// as `ddtelemetry::data::Configuration` payloads for telemetry collection.
/// It enables the configuration system to report configuration values, their
/// origins, and associated metadata to Datadog.
pub trait ConfigurationProvider {
    /// Returns all configurations that were set for this configuration item.
    /// e.g. If set through the environment variable,
    /// returns the environment variable config and the default config.
    fn get_all_configurations(&self) -> Vec<Configuration>;
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
    fn name(&self) -> SupportedConfigurations;
    /// Updates the configuration value while recording its source origin.
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin);
}

/// Configuration item that tracks the value of a setting and where it came from
/// This allows us to manage configuration precedence
#[derive(Debug)]
struct ConfigItem<T: ConfigurationValueProvider> {
    name: SupportedConfigurations,
    default_value: T,
    env_value: Option<T>,
    code_value: Option<T>,
    config_id: Option<String>,
}

impl<T: Clone + ConfigurationValueProvider> Clone for ConfigItem<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            default_value: self.default_value.clone(),
            env_value: self.env_value.clone(),
            code_value: self.code_value.clone(),
            config_id: self.config_id.clone(),
        }
    }
}

impl<T: Clone + ConfigurationValueProvider> ConfigItem<T> {
    /// Creates a new ConfigItem with a default value
    fn new(name: SupportedConfigurations, default: T) -> Self {
        Self {
            name,
            default_value: default,
            env_value: None,
            code_value: None,
            config_id: None,
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
    fn source(&self) -> ConfigSourceOrigin {
        if self.code_value.is_some() {
            ConfigSourceOrigin::Code
        } else if self.env_value.is_some() {
            ConfigSourceOrigin::EnvVar
        } else {
            ConfigSourceOrigin::Default
        }
    }

    fn is_default_value(&self) -> bool {
        self.source() == ConfigSourceOrigin::Default
    }

    /// Whether this configuration's value is excluded from configuration telemetry.
    fn is_sensitive(&self) -> bool {
        self.name.is_sensitive()
    }

    fn build_configurations_list(&self, calculated_value: Option<String>) -> Vec<Configuration> {
        let mut configurations = Vec::new();
        // Always include the default value
        configurations.push(Configuration {
            name: self.name.as_str().to_string(),
            value: self.default_value.get_configuration_value(),
            origin: ConfigSourceOrigin::Default.into(),
            config_id: self.config_id.clone(),
            seq_id: Some(ConfigSourceOrigin::Default as u64),
        });
        if let Some(calculated_value) = calculated_value {
            configurations.push(Configuration {
                name: self.name.as_str().to_string(),
                value: calculated_value,
                origin: ConfigSourceOrigin::Calculated.into(),
                config_id: self.config_id.clone(),
                seq_id: Some(ConfigSourceOrigin::Calculated as u64),
            });
        }
        if let Some(ref env_value) = self.env_value {
            configurations.push(Configuration {
                name: self.name.as_str().to_string(),
                value: env_value.get_configuration_value(),
                origin: ConfigSourceOrigin::EnvVar.into(),
                config_id: self.config_id.clone(),
                seq_id: Some(ConfigSourceOrigin::EnvVar as u64),
            });
        }
        if let Some(ref code_value) = self.code_value {
            configurations.push(Configuration {
                name: self.name.as_str().to_string(),
                value: code_value.get_configuration_value(),
                origin: ConfigSourceOrigin::Code.into(),
                config_id: self.config_id.clone(),
                seq_id: Some(ConfigSourceOrigin::Code as u64),
            });
        }
        configurations
    }
}

impl<T: Clone + ConfigurationValueProvider> ConfigurationProvider for ConfigItem<T> {
    /// Returns all configurations that were set for this configuration item.
    ///
    /// Configurations marked sensitive in the registry are excluded from
    /// configuration telemetry, so this returns an empty list for them.
    fn get_all_configurations(&self) -> Vec<Configuration> {
        if self.is_sensitive() {
            return Vec::new();
        }
        self.build_configurations_list(None)
    }
}

impl<T: ConfigurationValueProvider> ValueSourceUpdater<T> for ConfigItem<T> {
    fn name(&self) -> SupportedConfigurations {
        self.name
    }

    /// Sets a value from a specific source
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin) {
        match source {
            ConfigSourceOrigin::Code => self.code_value = Some(value),
            ConfigSourceOrigin::EnvVar => self.env_value = Some(value),
            ConfigSourceOrigin::Calculated => {
                dd_warn!("Cannot set a calculated value");
            }
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
struct ConfigItemWithOverride<T: ConfigurationValueProvider + Deref> {
    config_item: ConfigItem<T>,
    override_value: arc_swap::ArcSwapOption<T>,
    override_origin: ConfigSourceOrigin,
    config_id: arc_swap::ArcSwapOption<String>,
}

impl<T: Clone + ConfigurationValueProvider + Deref> Clone for ConfigItemWithOverride<T> {
    fn clone(&self) -> Self {
        Self {
            config_item: self.config_item.clone(),
            override_value: arc_swap::ArcSwapOption::new(self.override_value.load_full()),
            override_origin: self.override_origin,
            config_id: arc_swap::ArcSwapOption::new(self.config_id.load_full()),
        }
    }
}

impl<T: ConfigurationValueProvider + Clone + Deref> ConfigItemWithOverride<T> {
    fn new_calculated(name: SupportedConfigurations, default: T) -> Self {
        Self {
            config_item: ConfigItem::new(name, default),
            override_value: arc_swap::ArcSwapOption::const_empty(),
            override_origin: ConfigSourceOrigin::Calculated,
            config_id: arc_swap::ArcSwapOption::const_empty(),
        }
    }

    fn new_rc(name: SupportedConfigurations, default: T) -> Self {
        Self {
            config_item: ConfigItem::new(name, default),
            override_value: arc_swap::ArcSwapOption::const_empty(),
            override_origin: ConfigSourceOrigin::RemoteConfig,
            config_id: arc_swap::ArcSwapOption::const_empty(),
        }
    }

    /// Gets the source of the current value based on priority:
    /// remote_config > code > env_var > calculated > default
    fn source(&self) -> ConfigSourceOrigin {
        let config_item_source = self.config_item.source();
        if self.override_value.load().is_none() {
            config_item_source
        } else {
            config_item_source.max(self.override_origin)
        }
    }

    /// Replaces override value only if origin matches source_type
    fn set_override_value(&self, value: T, source: ConfigSourceOrigin) {
        if source == self.override_origin {
            self.override_value.store(Some(Arc::new(value)));
        }
    }

    fn set_config_id(&self, config_id: Option<String>) {
        match config_id {
            Some(id) => self.config_id.store(Some(Arc::new(id))),
            None => self.config_id.store(None),
        }
    }

    #[cfg(test)]
    /// Used for testing only
    fn get_config_id(&self) -> Option<String> {
        self.config_id.load().as_ref().map(|id| (**id).clone())
    }

    /// Unsets the override value
    fn unset_override_value(&self) {
        self.override_value.store(None);
    }

    /// Sets Code value only if source_type is Code
    fn set_code(&mut self, value: T) {
        self.set_value_source(value, ConfigSourceOrigin::Code);
    }

    /// Sets Calculated value only if source_type is Calculated
    fn set_calculated(&mut self, value: T) {
        self.set_value_source(value, ConfigSourceOrigin::Calculated);
    }

    /// Gets the current value based on priority:
    /// remote_config > code > env_var > calculated > default
    fn value(&self) -> ConfigItemRef<'_, T> {
        let override_value = self.override_value.load();
        if override_value.is_some() && self.source() == self.override_origin {
            ConfigItemRef::ArcRef(override_value)
        } else {
            ConfigItemRef::Ref(self.config_item.value())
        }
    }

    /// Returns the env/code/default value, ignoring any remote-config override.
    /// Use this when the caller must compose with RC-delivered values without
    /// losing the locally-configured value to the override.
    fn local_value(&self) -> ConfigItemRef<'_, T> {
        ConfigItemRef::Ref(self.config_item.value())
    }
}

impl<T: Clone + ConfigurationValueProvider + Deref> ConfigurationProvider
    for ConfigItemWithOverride<T>
{
    /// Returns all configurations that were set for this configuration item.
    ///
    /// Configurations marked sensitive in the registry are excluded from
    /// configuration telemetry, so this returns an empty list for them.
    fn get_all_configurations(&self) -> Vec<Configuration> {
        if self.config_item.is_sensitive() {
            return Vec::new();
        }
        // Also add override value if set
        let override_value = self.override_value.load();
        let calculated_option = if self.source() == ConfigSourceOrigin::Calculated {
            Some(override_value.as_ref().unwrap().get_configuration_value())
        } else {
            None
        };
        let mut configurations = self
            .config_item
            .build_configurations_list(calculated_option);
        if override_value.is_some() && self.source() != ConfigSourceOrigin::Calculated {
            let config_id = self.config_id.load().as_ref().map(|id| (**id).clone());
            configurations.push(Configuration {
                name: self.config_item.name.as_str().to_string(),
                value: self.value().get_configuration_value(),
                origin: self.source().into(),
                config_id,
                seq_id: Some(self.source() as u64),
            });
        }
        configurations
    }
}

impl<T: Clone + ConfigurationValueProvider + Deref> ValueSourceUpdater<T>
    for ConfigItemWithOverride<T>
{
    fn name(&self) -> SupportedConfigurations {
        self.config_item.name()
    }

    /// Sets a value from a specific source
    fn set_value_source(&mut self, value: T, source: ConfigSourceOrigin) {
        if source == self.override_origin {
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
    fn apply_result<ParsedConfig, RawConfig, ConfigItemType, F>(
        &self,
        mut item: ConfigItemType,
        result: CompositeConfigSourceResult<RawConfig>,
        transform: F,
    ) -> ConfigItemType
    where
        ParsedConfig: Clone + ConfigurationValueProvider,
        ConfigItemType: ValueSourceUpdater<ParsedConfig>,
        F: FnOnce(RawConfig) -> ParsedConfig,
    {
        if !result.errors.is_empty() {
            dd_error!(
                "Configuration: Error parsing property {} - {:?}",
                item.name().as_str(),
                result.errors
            );
        }

        if let Some(ConfigKey { value, origin }) = result.value {
            item.set_value_source(transform(value), origin);
        }
        item
    }

    /// Updates a ConfigItem from sources with parsed value (no transformation)
    fn update_parsed<ParsedConfig, ConfigItemType>(&self, default: ConfigItemType) -> ConfigItemType
    where
        ParsedConfig: Clone + FromStr + ConfigurationValueProvider,
        ParsedConfig::Err: std::fmt::Display,
        ConfigItemType: ValueSourceUpdater<ParsedConfig>,
    {
        let result = self.sources.get_parse::<ParsedConfig>(default.name());
        self.apply_result(default, result, |value| value)
    }

    /// Updates a ConfigItem from sources string with transformation
    pub fn update_string<ParsedConfig, ConfigItemType, F>(
        &self,
        default: ConfigItemType,
        transform: F,
    ) -> ConfigItemType
    where
        ParsedConfig: Clone + ConfigurationValueProvider,
        ConfigItemType: ValueSourceUpdater<ParsedConfig>,
        F: FnOnce(String) -> ParsedConfig,
    {
        let result = self.sources.get(default.name());
        self.apply_result(default, result, transform)
    }

    /// Updates a ConfigItem from non empty sources string with transformation
    pub fn update_non_empty_string<ParsedConfig, ConfigItemType, F>(
        &self,
        default: ConfigItemType,
        transform: F,
    ) -> ConfigItemType
    where
        ParsedConfig: Clone + ConfigurationValueProvider,
        ConfigItemType: ValueSourceUpdater<ParsedConfig>,
        F: FnOnce(String) -> ParsedConfig,
    {
        let result = self.sources.get(default.name());
        match result.value {
            Some(ref config_key) if config_key.value.is_empty() => default,
            Some(_) => self.apply_result(default, result, transform),
            None => default,
        }
    }

    /// Updates a ConfigItem from sources with parsed value and transformation
    pub fn update_parsed_with_transform<ParsedConfig, RawConfig, ConfigItemType, F>(
        &self,
        default: ConfigItemType,
        transform: F,
    ) -> ConfigItemType
    where
        ParsedConfig: Clone + ConfigurationValueProvider,
        RawConfig: FromStr,
        RawConfig::Err: std::fmt::Display,
        ConfigItemType: ValueSourceUpdater<ParsedConfig>,
        F: FnOnce(RawConfig) -> ParsedConfig,
    {
        let result = self.sources.get_parse::<RawConfig>(default.name());
        self.apply_result(default, result, transform)
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

    /// Returns true if `name` matches any tracked extra service
    /// (case-insensitively), checking both the resolved set and the pending
    /// queue. Read-only: does not drain the queue.
    fn contains_service(&self, name: &str) -> bool {
        if let Ok(set) = self.extra_services.lock() {
            if set.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                return true;
            }
        }
        if let Ok(queue) = self.extra_services_queue.lock() {
            if let Some(ref q) = *queue {
                if q.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                    return true;
                }
            }
        }
        false
    }

    fn add_extra_services(
        &self,
        services: impl Iterator<Item = impl Deref<Target = str>>,
        main_service: &str,
    ) {
        // first consume services with the same name as the service set in the config, as it is
        // already tracked by default before locking
        let mut services = services.filter(|s| s.deref() != main_service).peekable();
        if services.peek().is_none() {
            return;
        }
        let mut sent = match self.extra_services_sent.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut queue = match self.extra_services_queue.lock() {
            Ok(q) => q,
            Err(_) => return,
        };
        for service_name in services {
            let service_name = service_name.deref();
            if sent.contains(service_name) {
                continue;
            }
            // Add to queue and mark as sent
            if let Some(ref mut q) = *queue {
                q.push_back(service_name.to_string());
            }
            sent.insert(service_name.to_string());
        }
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

/// Trace context propagation style.
///
/// Defines how trace context is propagated across service boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracePropagationStyle {
    /// Datadog proprietary propagation format using `x-datadog-*` headers.
    Datadog,
    /// W3C Trace Context propagation format using `traceparent` and `tracestate` headers.
    TraceContext,
    /// W3C Baggage propagation format using the `baggage` header.
    Baggage,
    /// B3 multi-header propagation format using `x-b3-*` headers.
    B3Multi,
    /// B3 single-header propagation format using the `b3` header.
    B3SingleHeader,
    /// No propagation - trace context is not propagated.
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
            "baggage" => Ok(TracePropagationStyle::Baggage),
            "b3multi" => Ok(TracePropagationStyle::B3Multi),
            "b3" => Ok(TracePropagationStyle::B3SingleHeader),
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
            TracePropagationStyle::Baggage => "baggage",
            TracePropagationStyle::B3Multi => "b3multi",
            TracePropagationStyle::B3SingleHeader => "b3",
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

impl std::ops::Deref for ServiceName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Controls which baggage keys are promoted to span tags with a `"baggage."` prefix.
#[derive(Clone, Debug, PartialEq)]
pub enum BaggageTagKeyFilter {
    /// Empty string: no baggage keys are added as span tags.
    Disabled,
    /// `"*"`: every baggage key is added as a span tag.
    All,
    /// A non-empty, non-wildcard list of exact (case-sensitive) baggage key names.
    Keys(Vec<String>),
}

impl std::str::FromStr for BaggageTagKeyFilter {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            Ok(BaggageTagKeyFilter::Disabled)
        } else if trimmed == "*" {
            Ok(BaggageTagKeyFilter::All)
        } else {
            let keys: Vec<String> = trimmed
                .split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect();
            if keys.is_empty() {
                Ok(BaggageTagKeyFilter::Disabled)
            } else {
                Ok(BaggageTagKeyFilter::Keys(keys))
            }
        }
    }
}

impl ConfigurationValueProvider for BaggageTagKeyFilter {
    fn get_configuration_value(&self) -> String {
        match self {
            BaggageTagKeyFilter::Disabled => String::new(),
            BaggageTagKeyFilter::All => "*".to_string(),
            BaggageTagKeyFilter::Keys(keys) => keys.join(","),
        }
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

impl ConfigurationValueProvider for OtlpProtocol {
    fn get_configuration_value(&self) -> String {
        match self {
            OtlpProtocol::Grpc => "grpc",
            OtlpProtocol::HttpProtobuf => "http/protobuf",
            OtlpProtocol::HttpJson => "http/json",
        }
        .to_string()
    }
}

impl ConfigurationValueProvider for Option<OtlpProtocol> {
    fn get_configuration_value(&self) -> String {
        self.as_ref()
            .map(|p| p.get_configuration_value())
            .unwrap_or_default()
    }
}

impl ConfigurationValueProvider for opentelemetry_sdk::metrics::Temporality {
    fn get_configuration_value(&self) -> String {
        match self {
            opentelemetry_sdk::metrics::Temporality::Cumulative => "cumulative",
            opentelemetry_sdk::metrics::Temporality::Delta => "delta",
            _ => "delta",
        }
        .to_string()
    }
}

impl ConfigurationValueProvider for Option<opentelemetry_sdk::metrics::Temporality> {
    fn get_configuration_value(&self) -> String {
        self.as_ref()
            .map(|t| t.get_configuration_value())
            .unwrap_or_else(|| "delta".to_string())
    }
}

impl_config_value_provider!(simple: Cow<'static, str>, bool, u32, usize, i32, f64, ServiceName, LevelFilter, ParsedSamplingRules);
impl_config_value_provider!(option: String, f64);

#[derive(Clone)]
/// Configuration for the Datadog Tracer
///
/// # Usage
///
/// ```
/// use datadog_opentelemetry::configuration::Config;
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
    /// OTEL resource attributes parsed from OTEL_RESOURCE_ATTRIBUTES env var
    otel_resource_attributes: ConfigItem<Vec<(String, String)>>,
    /// OTEL metrics exporter type
    otel_metrics_exporter: ConfigItem<Cow<'static, str>>,
    /// OTEL metrics temporality preference
    otel_metrics_temporality_preference:
        ConfigItem<Option<opentelemetry_sdk::metrics::Temporality>>,
    /// host of the trace agent
    agent_host: ConfigItem<Cow<'static, str>>,
    /// port of the trace agent
    trace_agent_port: ConfigItem<u32>,
    /// url of the trace agent
    trace_agent_url: ConfigItemWithOverride<Cow<'static, str>>,
    /// host of the dogstatsd agent
    dogstatsd_agent_host: ConfigItem<Cow<'static, str>>,
    /// port of the dogstatsd agent
    dogstatsd_agent_port: ConfigItem<u32>,
    /// url of the dogstatsd agent
    dogstatsd_agent_url: ConfigItemWithOverride<Cow<'static, str>>,

    // # Sampling
    ///  A list of sampling rules. Each rule is matched against the root span of a trace
    /// If a rule matches, the trace is sampled with the associated sample rate.
    trace_sampling_rules: SamplingRulesConfigItem,

    /// Global trace sample rate (DD_TRACE_SAMPLE_RATE). `None` means unset
    /// (no implicit catch-all; libdatadog's no-rule path samples at 100%).
    /// `Some(rate)` installs a catch-all rule so the rate limiter applies.
    trace_sample_rate: ConfigItem<Option<f64>>,

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

    /// Whether to enable stats obfuscation for the tracer (for internal testing)
    trace_stats_computation_experimental_client_obfuscation_enabled: ConfigItem<bool>,

    /// Whether we wait for trace chunk to have been flushed to the agent before returning to
    /// the critical path of the app
    trace_writer_synchronous_write: bool,
    /// How long we wait for the synchronous export to be done
    trace_writer_synchronous_timeout: Duration,
    /// The max amount of time a span stays in the writer buffer before we trigger a flush
    trace_writer_max_flush_interval: Duration,

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

    /// Partial flush
    trace_partial_flush_enabled: ConfigItem<bool>,
    trace_partial_flush_min_spans: ConfigItem<usize>,

    /// Trace propagation configuration
    trace_propagation_style: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_style_extract: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_style_inject: ConfigItem<Option<Vec<TracePropagationStyle>>>,
    trace_propagation_extract_first: ConfigItem<bool>,

    /// Which baggage keys are promoted to span tags with a `"baggage."` prefix.
    trace_baggage_tag_keys: ConfigItem<BaggageTagKeyFilter>,

    /// Whether remote configuration is enabled
    remote_config_enabled: ConfigItem<bool>,

    /// Interval by with remote configuration is polled (seconds)
    /// 5 seconds is the highest interval allowed by the spec
    remote_config_poll_interval: ConfigItem<f64>,

    /// Tracks extra services discovered at runtime
    /// Used for remote configuration to report all services
    extra_services_tracker: ExtraServicesTracker,

    /// General callbacks to be called when configuration is updated from remote configuration
    /// Allows components like the DatadogSampler to be updated without circular imports
    remote_config_callbacks: Arc<Mutex<RemoteConfigCallbacks>>,

    /// Max length of x-datadog-tags header. It only accepts values between 0 and 512.
    /// The default value is 512 and x-datadog-tags header is not injected if value is 0.
    datadog_tags_max_length: ConfigItem<usize>,

    // # OpenTelemetry Metrics
    /// Enables OpenTelemetry metrics export
    metrics_otel_enabled: ConfigItem<bool>,
    /// OTLP metrics endpoint
    otlp_metrics_endpoint: ConfigItem<Cow<'static, str>>,
    /// OTLP general endpoint
    otlp_endpoint: ConfigItem<Cow<'static, str>>,
    /// OTLP general headers
    otlp_headers: ConfigItem<Cow<'static, str>>,
    /// OTLP metrics protocol (grpc, http/protobuf, http/json)
    otlp_metrics_protocol: ConfigItem<Option<OtlpProtocol>>,
    /// OTLP metrics headers
    otlp_metrics_headers: ConfigItem<Cow<'static, str>>,
    /// OTLP general protocol (fallback for metrics protocol)
    otlp_protocol: ConfigItem<Option<OtlpProtocol>>,
    /// OTLP metrics timeout in milliseconds
    otlp_metrics_timeout: ConfigItem<u32>,
    /// OTLP general timeout
    otlp_timeout: ConfigItem<u32>,
    /// Metric export interval in milliseconds
    metric_export_interval: ConfigItem<u32>,
    /// Metric export timeout in milliseconds
    metric_export_timeout: ConfigItem<u32>,

    // # OpenTelemetry Logs
    /// Enables OpenTelemetry logs export
    logs_otel_enabled: ConfigItem<bool>,
    /// OTEL logs exporter type
    otel_logs_exporter: ConfigItem<Cow<'static, str>>,
    /// OTLP logs endpoint
    otlp_logs_endpoint: ConfigItem<Cow<'static, str>>,
    /// OTLP logs headers
    otlp_logs_headers: ConfigItem<Cow<'static, str>>,
    /// OTLP logs protocol (grpc, http/protobuf, http/json)
    otlp_logs_protocol: ConfigItem<Option<OtlpProtocol>>,
    /// OTLP logs timeout in milliseconds
    otlp_logs_timeout: ConfigItem<u32>,
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

        struct OtelResourceAttributes(Vec<(String, String)>);

        impl FromStr for OtelResourceAttributes {
            type Err = &'static str;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(OtelResourceAttributes(
                    s.split(',')
                        .filter_map(|s| {
                            s.split_once('=')
                                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        })
                        .collect(),
                ))
            }
        }

        let parsed_sampling_rules_config = sources
            .get_parse::<ParsedSamplingRules>(SupportedConfigurations::DD_TRACE_SAMPLING_RULES);

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
            service: cisu.update_non_empty_string(default.service, ServiceName::Configured),
            env: cisu.update_string(default.env, Some),
            version: cisu.update_string(default.version, Some),
            // TODO(paullgdc): tags should be merged, not replaced
            global_tags: cisu
                .update_parsed_with_transform(default.global_tags, |DdKeyValueTags(tags)| tags),
            otel_resource_attributes: cisu.update_parsed_with_transform(
                default.otel_resource_attributes,
                |OtelResourceAttributes(attrs)| attrs,
            ),
            otel_metrics_exporter: cisu.update_string(default.otel_metrics_exporter, Cow::Owned),
            otel_metrics_temporality_preference: cisu.update_string(
                default.otel_metrics_temporality_preference,
                parse_temporality,
            ),
            agent_host: cisu.update_string(default.agent_host, Cow::Owned),
            trace_agent_port: cisu.update_parsed(default.trace_agent_port),
            trace_agent_url: cisu.update_non_empty_string(default.trace_agent_url, Cow::Owned),
            dogstatsd_agent_host: cisu.update_string(default.dogstatsd_agent_host, Cow::Owned),
            dogstatsd_agent_port: cisu.update_parsed(default.dogstatsd_agent_port),
            dogstatsd_agent_url: cisu
                .update_non_empty_string(default.dogstatsd_agent_url, Cow::Owned),

            trace_partial_flush_enabled: cisu.update_parsed(default.trace_partial_flush_enabled),
            trace_partial_flush_min_spans: cisu
                .update_parsed(default.trace_partial_flush_min_spans),

            // Use the initialized ConfigItem
            trace_sampling_rules: sampling_rules_item,
            trace_sample_rate: cisu.update_parsed_with_transform(
                default.trace_sample_rate,
                validate_trace_sample_rate,
            ),
            trace_rate_limit: cisu.update_parsed(default.trace_rate_limit),

            enabled: cisu.update_parsed(default.enabled),
            log_level_filter: cisu.update_parsed(default.log_level_filter),
            trace_stats_computation_enabled: cisu
                .update_parsed(default.trace_stats_computation_enabled),
            trace_stats_computation_experimental_client_obfuscation_enabled: cisu.update_parsed(
                default.trace_stats_computation_experimental_client_obfuscation_enabled,
            ),
            telemetry_enabled: cisu.update_parsed(default.telemetry_enabled),
            telemetry_log_collection_enabled: cisu
                .update_parsed(default.telemetry_log_collection_enabled),
            telemetry_heartbeat_interval: cisu.update_parsed_with_transform(
                default.telemetry_heartbeat_interval,
                |interval: f64| interval.abs(),
            ),
            trace_propagation_style: cisu
                .update_parsed_with_transform(default.trace_propagation_style, |DdTags(tags)| {
                    TracePropagationStyle::from_tags(Some(tags))
                }),
            trace_propagation_style_extract: cisu.update_parsed_with_transform(
                default.trace_propagation_style_extract,
                |DdTags(tags)| TracePropagationStyle::from_tags(Some(tags)),
            ),
            trace_propagation_style_inject: cisu.update_parsed_with_transform(
                default.trace_propagation_style_inject,
                |DdTags(tags)| TracePropagationStyle::from_tags(Some(tags)),
            ),
            trace_propagation_extract_first: cisu
                .update_parsed(default.trace_propagation_extract_first),
            trace_baggage_tag_keys: cisu.update_parsed(default.trace_baggage_tag_keys),
            trace_writer_synchronous_write: default.trace_writer_synchronous_write,
            trace_writer_synchronous_timeout: default.trace_writer_synchronous_timeout,
            trace_writer_max_flush_interval: default.trace_writer_max_flush_interval,
            #[cfg(feature = "test-utils")]
            wait_agent_info_ready: default.wait_agent_info_ready,
            extra_services_tracker: ExtraServicesTracker::new(),
            remote_config_enabled: cisu.update_parsed(default.remote_config_enabled),
            remote_config_poll_interval: cisu.update_parsed_with_transform(
                default.remote_config_poll_interval,
                |interval: f64| interval.abs().min(RC_DEFAULT_POLL_INTERVAL),
            ),
            remote_config_callbacks: Arc::new(Mutex::new(RemoteConfigCallbacks::new())),
            datadog_tags_max_length: cisu
                .update_parsed_with_transform(default.datadog_tags_max_length, |max: usize| {
                    max.min(DATADOG_TAGS_MAX_LENGTH)
                }),
            metrics_otel_enabled: cisu.update_parsed(default.metrics_otel_enabled),
            otlp_metrics_endpoint: cisu.update_string(default.otlp_metrics_endpoint, Cow::Owned),
            otlp_endpoint: cisu.update_string(default.otlp_endpoint, Cow::Owned),
            otlp_headers: cisu.update_string(default.otlp_headers, Cow::Owned),
            otlp_metrics_protocol: cisu
                .update_string(default.otlp_metrics_protocol, OtlpProtocol::parse_optional),
            otlp_metrics_headers: cisu.update_string(default.otlp_metrics_headers, Cow::Owned),
            otlp_protocol: cisu.update_string(default.otlp_protocol, OtlpProtocol::parse_optional),
            otlp_metrics_timeout: cisu.update_parsed(default.otlp_metrics_timeout),
            otlp_timeout: cisu.update_parsed(default.otlp_timeout),
            metric_export_interval: cisu.update_parsed(default.metric_export_interval),
            metric_export_timeout: cisu.update_parsed(default.metric_export_timeout),
            logs_otel_enabled: cisu.update_parsed(default.logs_otel_enabled),
            otel_logs_exporter: cisu.update_string(default.otel_logs_exporter, Cow::Owned),
            otlp_logs_endpoint: cisu.update_string(default.otlp_logs_endpoint, Cow::Owned),
            otlp_logs_headers: cisu.update_string(default.otlp_logs_headers, Cow::Owned),
            otlp_logs_protocol: cisu
                .update_string(default.otlp_logs_protocol, OtlpProtocol::parse_optional),
            otlp_logs_timeout: cisu.update_parsed(default.otlp_logs_timeout),
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

    pub(crate) fn get_telemetry_configuration(&self) -> Vec<&dyn ConfigurationProvider> {
        vec![
            &self.service,
            &self.env,
            &self.version,
            &self.global_tags,
            &self.agent_host,
            &self.trace_agent_port,
            &self.trace_agent_url,
            &self.dogstatsd_agent_host,
            &self.dogstatsd_agent_port,
            &self.dogstatsd_agent_url,
            &self.trace_sampling_rules,
            &self.trace_sample_rate,
            &self.trace_rate_limit,
            &self.enabled,
            &self.log_level_filter,
            &self.trace_stats_computation_enabled,
            &self.telemetry_enabled,
            &self.telemetry_log_collection_enabled,
            &self.telemetry_heartbeat_interval,
            &self.trace_partial_flush_enabled,
            &self.trace_partial_flush_min_spans,
            &self.trace_propagation_style,
            &self.trace_propagation_style_extract,
            &self.trace_propagation_style_inject,
            &self.trace_propagation_extract_first,
            &self.trace_baggage_tag_keys,
            &self.remote_config_enabled,
            &self.remote_config_poll_interval,
            &self.datadog_tags_max_length,
            &self.otlp_endpoint,
            &self.otlp_timeout,
            &self.otlp_headers,
            &self.otlp_protocol,
            &self.otlp_metrics_endpoint,
            &self.otlp_metrics_timeout,
            &self.otlp_metrics_headers,
            &self.otlp_metrics_protocol,
            &self.metric_export_interval,
            &self.metric_export_timeout,
            &self.logs_otel_enabled,
            &self.otel_logs_exporter,
            &self.otlp_logs_endpoint,
            &self.otlp_logs_headers,
            &self.otlp_logs_protocol,
            &self.otlp_logs_timeout,
        ]
    }

    /// Returns the unique runtime identifier for this process.
    pub fn runtime_id(&self) -> &str {
        self.runtime_id
    }

    /// Returns the version of the Datadog tracer.
    pub fn tracer_version(&self) -> &str {
        self.tracer_version
    }

    /// Returns the programming language identifier (e.g., "rust").
    pub fn language(&self) -> &str {
        self.language
    }

    /// Returns the version of the programming language runtime.
    pub fn language_version(&self) -> &str {
        self.language_version.as_str()
    }

    /// Returns the configured service name.
    pub fn service(&self) -> impl Deref<Target = str> + use<'_> {
        self.service.value()
    }

    /// Returns whether the service name is using the default value.
    pub fn service_is_default(&self) -> bool {
        match self.service.value() {
            ConfigItemRef::Ref(t) => t.is_default(),
            ConfigItemRef::ArcRef(guard) => guard.as_ref().unwrap().is_default(),
        }
    }

    /// Returns the configured environment name (e.g., "production", "staging").
    pub fn env(&self) -> Option<&str> {
        self.env.value().as_deref()
    }

    /// Returns the configured application version.
    pub fn version(&self) -> Option<&str> {
        self.version.value().as_deref()
    }

    /// Returns an iterator over the configured global tags as key-value pairs.
    pub fn global_tags(&self) -> impl Iterator<Item = (&str, &str)> {
        self.global_tags
            .value()
            .iter()
            .map(|tag| (tag.0.as_str(), tag.1.as_str()))
    }

    /// Returns OpenTelemetry resource attributes parsed from OTEL_RESOURCE_ATTRIBUTES env var.
    pub fn otel_resource_attributes(&self) -> impl Iterator<Item = (&str, &str)> {
        self.otel_resource_attributes
            .value()
            .iter()
            .map(|attr| (attr.0.as_str(), attr.1.as_str()))
    }

    /// Returns the OpenTelemetry metrics exporter type.
    pub fn otel_metrics_exporter(&self) -> &str {
        self.otel_metrics_exporter.value().as_ref()
    }

    /// Returns the OpenTelemetry metrics temporality preference (Delta or Cumulative).
    pub fn otel_metrics_temporality_preference(
        &self,
    ) -> Option<opentelemetry_sdk::metrics::Temporality> {
        *self.otel_metrics_temporality_preference.value()
    }

    /// Returns the URL of the Datadog trace agent.
    pub fn trace_agent_url(&self) -> impl Deref<Target = str> + use<'_> {
        self.trace_agent_url.value()
    }

    /// Returns the host of the DogStatsD agent.
    pub fn dogstatsd_agent_host(&self) -> &Cow<'static, str> {
        self.dogstatsd_agent_host.value()
    }

    /// Returns the port of the DogStatsD agent.
    pub fn dogstatsd_agent_port(&self) -> &u32 {
        self.dogstatsd_agent_port.value()
    }

    /// Returns the full URL of the DogStatsD agent.
    pub fn dogstatsd_agent_url(&self) -> impl Deref<Target = str> + use<'_> {
        self.dogstatsd_agent_url.value()
    }

    /// Returns the configured trace sampling rules.
    pub fn trace_sampling_rules(&self) -> impl Deref<Target = [SamplingRuleConfig]> + use<'_> {
        self.trace_sampling_rules.value()
    }

    /// Returns the locally-configured (env/code/default) trace sampling rules,
    /// ignoring any Remote Config override. Used by the RC handler to compose
    /// env rules with RC-delivered values without losing them.
    pub(crate) fn local_trace_sampling_rules(
        &self,
    ) -> impl Deref<Target = [SamplingRuleConfig]> + use<'_> {
        self.trace_sampling_rules.local_value()
    }

    /// Returns the maximum number of traces per second (rate limit).
    pub fn trace_rate_limit(&self) -> i32 {
        *self.trace_rate_limit.value()
    }

    /// Returns the configured global trace sample rate (DD_TRACE_SAMPLE_RATE),
    /// or `None` if unset. Applied as a catch-all sample rate when no explicit
    /// sampling rule matches.
    pub fn trace_sample_rate(&self) -> Option<f64> {
        *self.trace_sample_rate.value()
    }

    /// Returns whether tracing is enabled.
    pub fn enabled(&self) -> bool {
        *self.enabled.value()
    }

    /// Returns the configured log level filter.
    pub fn log_level_filter(&self) -> &LevelFilter {
        self.log_level_filter.value()
    }

    /// Returns whether client-side trace stats obfuscation is enabled.
    pub fn trace_stats_computation_experimental_client_obfuscation_enabled(&self) -> bool {
        *self
            .trace_stats_computation_experimental_client_obfuscation_enabled
            .value()
    }

    /// Returns whether client-side trace stats computation is enabled.
    pub fn trace_stats_computation_enabled(&self) -> bool {
        *self.trace_stats_computation_enabled.value()
    }

    pub(crate) fn trace_writer_synchronous_write(&self) -> bool {
        self.trace_writer_synchronous_write
    }

    pub(crate) fn trace_writer_synchronous_timeout(&self) -> Duration {
        self.trace_writer_synchronous_timeout
    }

    pub(crate) fn trace_writer_max_flush_interval(&self) -> Duration {
        self.trace_writer_max_flush_interval
    }

    #[cfg(feature = "test-utils")]
    pub(crate) fn __internal_wait_agent_info_ready(&self) -> bool {
        self.wait_agent_info_ready
    }

    /// Static runtime id if the process
    fn process_runtime_id() -> &'static str {
        // TODO(paullgdc): Regenerate on fork? Would we even support forks?
        static RUNTIME_ID: OnceLock<String> = OnceLock::new();
        RUNTIME_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
    }

    /// Returns whether telemetry collection is enabled.
    pub fn telemetry_enabled(&self) -> bool {
        *self.telemetry_enabled.value()
    }

    /// Returns whether telemetry log collection is enabled.
    pub fn telemetry_log_collection_enabled(&self) -> bool {
        *self.telemetry_log_collection_enabled.value()
    }

    /// Returns the telemetry heartbeat interval in seconds.
    pub fn telemetry_heartbeat_interval(&self) -> f64 {
        *self.telemetry_heartbeat_interval.value()
    }

    /// Returns whether OpenTelemetry metrics export is enabled.
    pub fn metrics_otel_enabled(&self) -> bool {
        *self.metrics_otel_enabled.value()
    }

    /// Returns the OTLP metrics endpoint URL.
    pub fn otlp_metrics_endpoint(&self) -> &str {
        self.otlp_metrics_endpoint.value().as_ref()
    }

    /// Returns the OTLP endpoint URL (fallback for metrics if metrics endpoint is not set).
    pub fn otlp_endpoint(&self) -> &str {
        self.otlp_endpoint.value().as_ref()
    }

    /// Returns the OTLP headers (fallback for metrics if metrics headers are not set).
    pub fn otlp_headers(&self) -> &str {
        self.otlp_headers.value().as_ref()
    }

    /// Returns the OTLP metrics protocol (gRPC, HTTP/protobuf, or HTTP/JSON).
    pub fn otlp_metrics_protocol(&self) -> Option<OtlpProtocol> {
        *self.otlp_metrics_protocol.value()
    }

    /// Returns the OTLP metrics headers.
    pub fn otlp_metrics_headers(&self) -> &str {
        self.otlp_metrics_headers.value().as_ref()
    }

    /// Returns the OTLP protocol (fallback for metrics if metrics protocol is not set).
    pub fn otlp_protocol(&self) -> Option<OtlpProtocol> {
        *self.otlp_protocol.value()
    }

    /// Returns the OTLP metrics timeout in milliseconds.
    pub fn otlp_metrics_timeout(&self) -> u32 {
        *self.otlp_metrics_timeout.value()
    }

    /// Returns the OTLP timeout in milliseconds (fallback for metrics if metrics timeout is not
    /// set).
    pub fn otlp_timeout(&self) -> u32 {
        *self.otlp_timeout.value()
    }

    /// Returns the metric export interval in milliseconds.
    pub fn metric_export_interval(&self) -> u32 {
        *self.metric_export_interval.value()
    }

    /// Returns the metric export timeout in milliseconds.
    pub fn metric_export_timeout(&self) -> u32 {
        *self.metric_export_timeout.value()
    }

    /// Returns whether OpenTelemetry logs export is enabled.
    pub fn logs_otel_enabled(&self) -> bool {
        *self.logs_otel_enabled.value()
    }

    /// Returns the OpenTelemetry logs exporter type.
    pub fn otel_logs_exporter(&self) -> &str {
        self.otel_logs_exporter.value().as_ref()
    }

    /// Returns the OTLP logs endpoint URL.
    pub fn otlp_logs_endpoint(&self) -> &str {
        self.otlp_logs_endpoint.value().as_ref()
    }

    /// Returns the OTLP logs headers.
    pub fn otlp_logs_headers(&self) -> &str {
        self.otlp_logs_headers.value().as_ref()
    }

    /// Returns the OTLP logs protocol.
    pub fn otlp_logs_protocol(&self) -> Option<OtlpProtocol> {
        *self.otlp_logs_protocol.value()
    }

    /// Returns the OTLP logs timeout in milliseconds.
    pub fn otlp_logs_timeout(&self) -> u32 {
        *self.otlp_logs_timeout.value()
    }

    /// Returns whether partial trace flushing is enabled.
    pub fn trace_partial_flush_enabled(&self) -> bool {
        *self.trace_partial_flush_enabled.value()
    }

    /// Returns the minimum number of spans required to trigger a partial flush.
    pub fn trace_partial_flush_min_spans(&self) -> usize {
        *self.trace_partial_flush_min_spans.value()
    }

    /// Returns the configured trace propagation styles for both injection and extraction.
    pub fn trace_propagation_style(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style.value().as_deref()
    }

    /// Returns the configured trace propagation styles for context extraction.
    pub fn trace_propagation_style_extract(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_extract.value().as_deref()
    }

    /// Returns the configured trace propagation styles for context injection.
    pub fn trace_propagation_style_inject(&self) -> Option<&[TracePropagationStyle]> {
        self.trace_propagation_style_inject.value().as_deref()
    }

    /// Returns whether to stop extraction after the first successful propagator.
    pub fn trace_propagation_extract_first(&self) -> bool {
        *self.trace_propagation_extract_first.value()
    }

    /// Returns which baggage keys should be promoted to span tags.
    pub fn trace_baggage_tag_keys(&self) -> &BaggageTagKeyFilter {
        self.trace_baggage_tag_keys.value()
    }

    pub(crate) fn update_sampling_rules_from_remote(
        &self,
        rules_json: &str,
        config_id: Option<String>,
    ) -> Result<(), String> {
        // Parse the JSON into the internal type to preserve provenance from remote config.
        let internal_rules: Vec<libdd_sampling::SamplingRuleConfig> =
            serde_json::from_str(rules_json)
                .map_err(|e| format!("Failed to parse sampling rules JSON: {e}"))?;

        // If remote config sends empty rules, clear remote config to fall back to local rules
        if internal_rules.is_empty() {
            self.clear_remote_sampling_rules(config_id);
        } else {
            // Convert to public type for storage (provenance is dropped).
            let rules: Vec<SamplingRuleConfig> =
                internal_rules.iter().cloned().map(Into::into).collect();
            self.trace_sampling_rules.set_override_value(
                ParsedSamplingRules { rules },
                ConfigSourceOrigin::RemoteConfig,
            );
            self.trace_sampling_rules.set_config_id(config_id);

            // Notify callbacks with the internal rules (preserves provenance)
            self.remote_config_callbacks
                .lock()
                .unwrap()
                .notify_update(&RemoteConfigUpdate::SamplingRules(internal_rules));

            telemetry::notify_configuration_update(&self.trace_sampling_rules);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn update_service_name(&self, service_name: Option<String>) {
        if let Some(service_name) = service_name {
            self.service.set_override_value(
                ServiceName::Configured(service_name),
                ConfigSourceOrigin::Code,
            );
        }
    }

    /// Sets the service name to a value with calculated precedence.
    /// The value is calculated by the `dd_resource` Otel Resource,
    /// which is created in `create_dd_resource` function.
    /// The result will depend on which environment variable was set,
    /// or if it returns an `unknown_service` name, which is why it is a calculated source.
    pub(crate) fn set_calculated_service_name(&self, service_name: Option<String>) {
        if let Some(service_name) = service_name {
            self.service.set_override_value(
                ServiceName::Configured(service_name),
                ConfigSourceOrigin::Calculated,
            );
        }
    }

    /// Composes the rules that the sampler should see in the absence of any
    /// active Remote Config override: locally-configured rules followed by an
    /// implicit catch-all that applies `DD_TRACE_SAMPLE_RATE`.
    ///
    /// The catch-all is appended only when `DD_TRACE_SAMPLE_RATE` is explicitly
    /// set. Its default is unset (`None`), in which case nothing is appended and
    /// libdatadog's no-rule fallback samples unmatched spans at 100%. An explicit
    /// value — including `1.0` — does install the catch-all, so `DD_TRACE_RATE_LIMIT`
    /// applies to otherwise-unmatched spans. The rate is already validated to a
    /// finite value in `[0.0, 1.0]` at ingestion; the `is_finite` guard below is
    /// belt-and-suspenders.
    pub(crate) fn effective_initial_rules(&self) -> Vec<libdd_sampling::SamplingRuleConfig> {
        let mut rules: Vec<libdd_sampling::SamplingRuleConfig> = self
            .local_trace_sampling_rules()
            .iter()
            .cloned()
            .map(Into::into)
            .collect();
        if let Some(env_rate) = self.trace_sample_rate() {
            if env_rate.is_finite() {
                rules.push(libdd_sampling::SamplingRuleConfig {
                    sample_rate: env_rate,
                    service: None,
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    // "default" is libdatadog's documented default provenance
                    // (default_provenance() in libdd-sampling) and matches the
                    // value the RC-rate catch-all path produces via serde omission.
                    provenance: "default".to_string(),
                });
            }
        }
        rules
    }

    pub(crate) fn clear_remote_sampling_rules(&self, config_id: Option<String>) {
        self.trace_sampling_rules.unset_override_value();
        self.trace_sampling_rules.set_config_id(config_id);

        let internal = self.effective_initial_rules();
        self.remote_config_callbacks
            .lock()
            .unwrap()
            .notify_update(&RemoteConfigUpdate::SamplingRules(internal));

        telemetry::notify_configuration_update(&self.trace_sampling_rules);
    }

    /// Add a callback to be called when sampling rules are updated via remote configuration
    /// This allows components like DatadogSampler to be updated without circular imports
    ///
    /// # Arguments
    /// * `callback` - The function to call when sampling rules are updated (receives
    ///   RemoteConfigUpdate enum)
    pub(crate) fn set_sampling_rules_callback<F>(&self, callback: F)
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
    pub(crate) fn add_extra_services(
        &self,
        service_names: impl Iterator<Item = impl Deref<Target = str>>,
    ) {
        if !self.remote_config_enabled() {
            return;
        }
        self.extra_services_tracker
            .add_extra_services(service_names, self.service().deref());
    }

    /// Get all extra services discovered at runtime
    pub(crate) fn get_extra_services(&self) -> Vec<String> {
        if !self.remote_config_enabled() {
            return Vec::new();
        }
        self.extra_services_tracker.get_extra_services()
    }

    /// Returns true if an RC `service_target.service` value applies to this
    /// tracer: it matches the primary service or any advertised extra service,
    /// compared case-insensitively. Used to guard which Remote Config sampling
    /// payloads this tracer applies (a config that advertised extra service is
    /// legitimately ours; service-name case can differ from the UI).
    pub(crate) fn rc_service_target_matches(&self, target_service: &str) -> bool {
        target_service.eq_ignore_ascii_case(&self.service())
            || self.extra_services_tracker.contains_service(target_service)
    }

    /// Check if remote configuration is enabled
    pub fn remote_config_enabled(&self) -> bool {
        *self.remote_config_enabled.value()
    }

    /// Get RC poll interval (seconds)
    pub fn remote_config_poll_interval(&self) -> f64 {
        *self.remote_config_poll_interval.value()
    }

    /// Return tags max length
    pub fn datadog_tags_max_length(&self) -> usize {
        *self.datadog_tags_max_length.value()
    }

    /// Generate tracer metadata from this config.
    #[cfg(target_os = "linux")]
    pub(crate) fn to_tracer_metadata(&self) -> TracerMetadata {
        fn hostname() -> String {
            let mut buf = vec![0; 256];

            unsafe {
                // Safety: buf is valid for writes for at most buf.len().
                if libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) == 0 {
                    // Amusingly (so to speak), if the host name doesn't fit in `buf.len()`,
                    // gethostname will put a truncated version in the buffer, which isn't
                    // null-terminated. So the resulting buffer might or might not be a valid C
                    // string...
                    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                    buf.truncate(len);
                    // Note: use from_utf8_lossy_owned once it's stabilized
                    String::from_utf8(buf)
                        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
                } else {
                    String::new()
                }
            }
        }

        TracerMetadata {
            runtime_id: Some(self.runtime_id.to_owned()),
            tracer_language: "rust".to_owned(),
            tracer_version: self.tracer_version.to_owned(),
            hostname: hostname(),
            service_name: Some(self.service().to_owned()),
            service_env: self.env().map(str::to_owned),
            service_version: self.version().map(str::to_owned),
            container_id: libdd_common::entity_id::get_container_id().map(str::to_owned),
            // TODO: add the process tags. For now, we can't easily get them.
            ..Default::default()
        }
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
            .field("trace_sample_rate", &self.trace_sample_rate)
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
            .field("trace_baggage_tag_keys", &self.trace_baggage_tag_keys)
            .field("extra_services_tracker", &self.extra_services_tracker)
            .field("remote_config_enabled", &self.remote_config_enabled)
            .field(
                "remote_config_poll_interval",
                &self.remote_config_poll_interval,
            )
            .field("remote_config_callbacks", &self.remote_config_callbacks)
            .finish()
    }
}

fn default_config() -> Config {
    Config {
        runtime_id: Config::process_runtime_id(),
        env: ConfigItem::new(SupportedConfigurations::DD_ENV, None),
        // TODO(paullgdc): Default service naming detection, probably from arg0
        service: ConfigItemWithOverride::new_calculated(
            SupportedConfigurations::DD_SERVICE,
            ServiceName::Default,
        ),
        version: ConfigItem::new(SupportedConfigurations::DD_VERSION, None),
        global_tags: ConfigItem::new(SupportedConfigurations::DD_TAGS, Vec::new()),
        otel_resource_attributes: ConfigItem::new(
            SupportedConfigurations::OTEL_RESOURCE_ATTRIBUTES,
            Vec::new(),
        ),
        otel_metrics_exporter: ConfigItem::new(
            SupportedConfigurations::OTEL_METRICS_EXPORTER,
            Cow::Borrowed("otlp"),
        ),
        otel_metrics_temporality_preference: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE,
            Some(opentelemetry_sdk::metrics::Temporality::Delta),
        ),

        agent_host: ConfigItem::new(
            SupportedConfigurations::DD_AGENT_HOST,
            Cow::Borrowed("localhost"),
        ),
        trace_agent_port: ConfigItem::new(SupportedConfigurations::DD_TRACE_AGENT_PORT, 8126),
        trace_agent_url: ConfigItemWithOverride::new_calculated(
            SupportedConfigurations::DD_TRACE_AGENT_URL,
            Cow::Borrowed(""),
        ),
        dogstatsd_agent_host: ConfigItem::new(
            SupportedConfigurations::DD_DOGSTATSD_HOST,
            Cow::Borrowed("localhost"),
        ),
        dogstatsd_agent_port: ConfigItem::new(SupportedConfigurations::DD_DOGSTATSD_PORT, 8125),
        dogstatsd_agent_url: ConfigItemWithOverride::new_calculated(
            SupportedConfigurations::DD_DOGSTATSD_URL,
            Cow::Borrowed(""),
        ),
        trace_sampling_rules: ConfigItemWithOverride::new_rc(
            SupportedConfigurations::DD_TRACE_SAMPLING_RULES,
            ParsedSamplingRules::default(), // Empty rules by default
        ),
        trace_sample_rate: ConfigItem::new(SupportedConfigurations::DD_TRACE_SAMPLE_RATE, None),
        trace_rate_limit: ConfigItem::new(SupportedConfigurations::DD_TRACE_RATE_LIMIT, 100),
        enabled: ConfigItem::new(SupportedConfigurations::DD_TRACE_ENABLED, true),
        log_level_filter: ConfigItem::new(
            SupportedConfigurations::DD_LOG_LEVEL,
            LevelFilter::default(),
        ),
        tracer_version: TRACER_VERSION,
        language: "rust",
        language_version: version().to_string(),
        trace_stats_computation_enabled: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_STATS_COMPUTATION_ENABLED,
            true,
        ),
        trace_stats_computation_experimental_client_obfuscation_enabled: ConfigItem::new(
            SupportedConfigurations::_DD_TRACE_STATS_COMPUTATION_EXPERIMENTAL_CLIENT_OBFUSCATION_ENABLED,
            false,
        ),
        trace_writer_synchronous_write: false,
        trace_writer_synchronous_timeout: Duration::from_secs(2),
        trace_writer_max_flush_interval: Duration::from_secs(1),
        #[cfg(feature = "test-utils")]
        wait_agent_info_ready: false,

        telemetry_enabled: ConfigItem::new(
            SupportedConfigurations::DD_INSTRUMENTATION_TELEMETRY_ENABLED,
            true,
        ),
        telemetry_log_collection_enabled: ConfigItem::new(
            SupportedConfigurations::DD_TELEMETRY_LOG_COLLECTION_ENABLED,
            true,
        ),
        telemetry_heartbeat_interval: ConfigItem::new(
            SupportedConfigurations::DD_TELEMETRY_HEARTBEAT_INTERVAL,
            60.0,
        ),
        trace_partial_flush_enabled: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PARTIAL_FLUSH_ENABLED,
            false,
        ),
        trace_partial_flush_min_spans: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PARTIAL_FLUSH_MIN_SPANS,
            300,
        ),
        trace_propagation_style: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PROPAGATION_STYLE,
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::Baggage,
            ]),
        ),
        trace_propagation_style_extract: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PROPAGATION_STYLE_EXTRACT,
            None,
        ),
        trace_propagation_style_inject: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PROPAGATION_STYLE_INJECT,
            None,
        ),
        trace_propagation_extract_first: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_PROPAGATION_EXTRACT_FIRST,
            false,
        ),
        trace_baggage_tag_keys: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_BAGGAGE_TAG_KEYS,
            BaggageTagKeyFilter::Keys(vec![
                "user.id".to_string(),
                "session.id".to_string(),
                "account.id".to_string(),
            ]),
        ),
        extra_services_tracker: ExtraServicesTracker::new(),
        remote_config_enabled: ConfigItem::new(
            SupportedConfigurations::DD_REMOTE_CONFIGURATION_ENABLED,
            true,
        ),
        remote_config_poll_interval: ConfigItem::new(
            SupportedConfigurations::DD_REMOTE_CONFIG_POLL_INTERVAL_SECONDS,
            RC_DEFAULT_POLL_INTERVAL,
        ),
        remote_config_callbacks: Arc::new(Mutex::new(RemoteConfigCallbacks::new())),
        datadog_tags_max_length: ConfigItem::new(
            SupportedConfigurations::DD_TRACE_X_DATADOG_TAGS_MAX_LENGTH,
            DATADOG_TAGS_MAX_LENGTH,
        ),
        metrics_otel_enabled: ConfigItem::new(
            SupportedConfigurations::DD_METRICS_OTEL_ENABLED,
            true,
        ),
        otlp_metrics_endpoint: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,
            Cow::Borrowed(""),
        ),
        otlp_endpoint: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_ENDPOINT,
            Cow::Borrowed(""),
        ),
        otlp_headers: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_HEADERS,
            Cow::Borrowed(""),
        ),
        otlp_metrics_protocol: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_METRICS_PROTOCOL,
            None,
        ),
        otlp_metrics_headers: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_METRICS_HEADERS,
            Cow::Borrowed(""),
        ),
        otlp_protocol: ConfigItem::new(SupportedConfigurations::OTEL_EXPORTER_OTLP_PROTOCOL, None),
        otlp_metrics_timeout: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_METRICS_TIMEOUT,
            10000u32,
        ),
        otlp_timeout: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_TIMEOUT,
            10000u32,
        ),
        metric_export_interval: ConfigItem::new(
            SupportedConfigurations::OTEL_METRIC_EXPORT_INTERVAL,
            10000u32,
        ),
        metric_export_timeout: ConfigItem::new(
            SupportedConfigurations::OTEL_METRIC_EXPORT_TIMEOUT,
            7500u32,
        ),
        logs_otel_enabled: ConfigItem::new(SupportedConfigurations::DD_LOGS_OTEL_ENABLED, true),
        otel_logs_exporter: ConfigItem::new(
            SupportedConfigurations::OTEL_LOGS_EXPORTER,
            Cow::Borrowed("otlp"),
        ),
        otlp_logs_endpoint: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_LOGS_ENDPOINT,
            Cow::Borrowed(""),
        ),
        otlp_logs_headers: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_LOGS_HEADERS,
            Cow::Borrowed(""),
        ),
        otlp_logs_protocol: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_LOGS_PROTOCOL,
            None,
        ),
        otlp_logs_timeout: ConfigItem::new(
            SupportedConfigurations::OTEL_EXPORTER_OTLP_LOGS_TIMEOUT,
            10000u32,
        ),
    }
}

/// Builder for constructing a [`Config`] instance.
///
/// Use [`Config::builder()`] to create a new builder instance.
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Finalizes the builder and returns the configuration
    pub fn build(&self) -> Config {
        crate::core::log::set_max_level(*self.config.log_level_filter.value());
        let mut config = self.config.clone();

        // resolve trace_agent_url
        // this will send the the config through telemetry with `calculated` origin.
        if config.trace_agent_url.value().is_empty() {
            let uds_is_alive = Path::new(DEFAULT_UNIX_TRACE_AGENT_URL)
                .try_exists()
                .unwrap_or(false);

            // if user hasn't provided agent_host nor agent_port and UDS is alive, use it
            let url = if config.agent_host.is_default_value()
                && config.trace_agent_port.is_default_value()
                && uds_is_alive
            {
                Cow::Owned(format!("unix://{DEFAULT_UNIX_TRACE_AGENT_URL}"))
            } else {
                let host = &config.agent_host.value();
                let port = *config.trace_agent_port.value();
                Cow::Owned(format!("http://{host}:{port}"))
            };
            config.trace_agent_url.set_calculated(url);
        }

        // resolve dogstatsd_agent_url
        // this will send the the config through telemetry with `calculated` origin.
        if config.dogstatsd_agent_url.value().is_empty() {
            let uds_is_alive = Path::new(DEFAULT_UNIX_DOGSTATSD_AGENT_URL)
                .try_exists()
                .unwrap_or(false);

            // if user hasn't provided agent_host nor agent_port and UDS is alive, use it
            let url = if config.agent_host.is_default_value()
                && config.trace_agent_port.is_default_value()
                && uds_is_alive
            {
                Cow::Owned(format!("unix://{DEFAULT_UNIX_DOGSTATSD_AGENT_URL}"))
            } else {
                let host = &config.dogstatsd_agent_host.value();
                let port = *config.dogstatsd_agent_port.value();
                Cow::Owned(format!("http://{host}:{port}"))
            };
            config.dogstatsd_agent_url.set_calculated(url);
        }

        config
    }

    /// Sets the service name for your application
    ///
    /// **Default**: `unnamed-rust-service`
    ///
    /// Env variable: `DD_SERVICE`
    pub fn set_service(&mut self, service: String) -> &mut Self {
        self.config
            .service
            .set_code(ServiceName::Configured(service));
        self
    }

    /// Set the application's environment, for example: `prod`, `staging`.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `DD_ENV`
    pub fn set_env(&mut self, env: String) -> &mut Self {
        self.config.env.set_code(Some(env));
        self
    }

    /// Set the application's version, for example: `1.2.3` or `6c44da20`.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `DD_VERSION`
    pub fn set_version(&mut self, version: String) -> &mut Self {
        self.config.version.set_code(Some(version));
        self
    }

    /// A list of default tags to be added to every span, in `(key, value)` format. Example:
    /// `[(layer, api), (team, intake)]`.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `DD_TAGS`
    pub fn set_global_tags(&mut self, tags: Vec<(String, String)>) -> &mut Self {
        self.config.global_tags.set_code(tags);
        self
    }

    /// Add a tag to be added to every span, in `(key, value)` format.
    /// Example: `(layer, api)`.
    pub fn add_global_tag(&mut self, tag: (String, String)) -> &mut Self {
        let mut current_tags = self.config.global_tags.value().clone();
        current_tags.push(tag);
        self.config.global_tags.set_code(current_tags);
        self
    }

    /// Set OpenTelemetry resource attributes as a list of `(key, value)` pairs.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `OTEL_RESOURCE_ATTRIBUTES`
    pub fn set_otel_resource_attributes(&mut self, attributes: Vec<(String, String)>) -> &mut Self {
        self.config.otel_resource_attributes.set_code(attributes);
        self
    }

    /// Enable or disable telemetry data collection and sending.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_INSTRUMENTATION_TELEMETRY_ENABLED`
    pub fn set_telemetry_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.telemetry_enabled.set_code(enabled);
        self
    }

    /// Enable or disable log collection for telemetry.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_TELEMETRY_LOG_COLLECTION_ENABLED`
    pub fn set_telemetry_log_collection_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config
            .telemetry_log_collection_enabled
            .set_code(enabled);
        self
    }

    /// Interval in seconds for sending telemetry heartbeat messages.
    ///
    ///  **Default**: `60.0`
    ///
    /// Env variable: `DD_TELEMETRY_HEARTBEAT_INTERVAL`
    pub fn set_telemetry_heartbeat_interval(&mut self, seconds: f64) -> &mut Self {
        self.config
            .telemetry_heartbeat_interval
            .set_code(seconds.abs());
        self
    }

    /// Sets the hostname of the Datadog Agent.
    ///
    ///  **Default**: `localhost`
    ///
    /// Env variable: `DD_AGENT_HOST`
    pub fn set_agent_host(&mut self, host: String) -> &mut Self {
        self.config
            .agent_host
            .set_code(Cow::Owned(host.to_string()));
        self
    }

    /// Sets the port of the Datadog Agent for trace collection.
    ///
    ///  **Default**: `8126`
    ///
    /// Env variable: `DD_TRACE_AGENT_PORT`
    pub fn set_trace_agent_port(&mut self, port: u32) -> &mut Self {
        self.config.trace_agent_port.set_code(port);
        self
    }

    /// Sets the URL of the Datadog Agent. This takes precedence over `DD_AGENT_HOST` and
    /// `DD_TRACE_AGENT_PORT`.
    ///
    ///  **Default**: `http://localhost:8126`
    ///
    /// Env variable: `DD_TRACE_AGENT_URL`
    pub fn set_trace_agent_url(&mut self, url: String) -> &mut Self {
        self.config
            .trace_agent_url
            .set_code(Cow::Owned(url.to_string()));
        self
    }

    /// Enable or disable OpenTelemetry metrics export.
    ///
    /// **Default**: `false`
    ///
    /// Env variable: `DD_METRICS_OTEL_ENABLED`
    pub fn set_metrics_otel_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.metrics_otel_enabled.set_code(enabled);
        self
    }

    /// Set the OTLP metrics endpoint URL.
    ///
    /// **Default**: `(empty, falls back to OTEL_EXPORTER_OTLP_ENDPOINT or agent URL)`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
    pub fn set_otlp_metrics_endpoint(&mut self, endpoint: String) -> &mut Self {
        self.config
            .otlp_metrics_endpoint
            .set_code(Cow::Owned(endpoint));
        self
    }

    /// Set the OTLP general endpoint URL (fallback for metrics endpoint).
    ///
    /// **Default**: `(empty)`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_ENDPOINT`
    pub fn set_otlp_endpoint(&mut self, endpoint: String) -> &mut Self {
        self.config.otlp_endpoint.set_code(Cow::Owned(endpoint));
        self
    }

    /// Set the OTLP metrics protocol (grpc, http/protobuf, http/json).
    ///
    /// **Default**: `(empty, defaults to grpc)`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL`
    pub fn set_otlp_metrics_protocol(&mut self, protocol: String) -> &mut Self {
        self.config
            .otlp_metrics_protocol
            .set_code(OtlpProtocol::parse_optional(protocol));
        self
    }

    /// Set the OTLP general protocol (fallback for metrics protocol).
    ///
    /// **Default**: `(empty)`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_PROTOCOL`
    pub fn set_otlp_protocol(&mut self, protocol: String) -> &mut Self {
        self.config
            .otlp_protocol
            .set_code(OtlpProtocol::parse_optional(protocol));
        self
    }

    /// Set the OTLP metrics timeout in milliseconds.
    ///
    /// **Default**: `7500`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_METRICS_TIMEOUT`
    pub fn set_otlp_metrics_timeout(&mut self, timeout: u32) -> &mut Self {
        self.config.otlp_metrics_timeout.set_code(timeout);
        self
    }

    /// Set the OTLP general timeout in milliseconds (fallback for metrics timeout).
    ///
    /// **Default**: `7500`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_TIMEOUT`
    pub fn set_otlp_timeout(&mut self, timeout: u32) -> &mut Self {
        self.config.otlp_timeout.set_code(timeout);
        self
    }

    /// Enable or disable OpenTelemetry logs export.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_LOGS_OTEL_ENABLED`
    pub fn set_logs_otel_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.logs_otel_enabled.set_code(enabled);
        self
    }

    /// Set the OTLP logs endpoint URL.
    ///
    /// **Default**: `""`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`
    pub fn set_otlp_logs_endpoint(&mut self, endpoint: String) -> &mut Self {
        self.config
            .otlp_logs_endpoint
            .set_code(Cow::Owned(endpoint));
        self
    }

    /// Set the OTLP logs protocol (grpc, http/protobuf, http/json).
    ///
    /// **Default**: `None` (falls back to `OTEL_EXPORTER_OTLP_PROTOCOL`)
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_LOGS_PROTOCOL`
    pub fn set_otlp_logs_protocol(&mut self, protocol: String) -> &mut Self {
        self.config
            .otlp_logs_protocol
            .set_code(OtlpProtocol::parse_optional(protocol));
        self
    }

    /// Set the OTLP logs timeout in milliseconds.
    ///
    /// **Default**: `10000`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_LOGS_TIMEOUT`
    pub fn set_otlp_logs_timeout(&mut self, timeout: u32) -> &mut Self {
        self.config.otlp_logs_timeout.set_code(timeout);
        self
    }

    /// Set the OTLP metrics temporality preference.
    ///
    /// **Default**: `Delta`
    ///
    /// Env variable: `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE`
    pub fn set_otel_metrics_temporality_preference(
        &mut self,
        temporality: opentelemetry_sdk::metrics::Temporality,
    ) -> &mut Self {
        self.config
            .otel_metrics_temporality_preference
            .set_code(Some(temporality));
        self
    }

    /// Set the metric export interval in milliseconds.
    ///
    /// **Default**: `10000`
    ///
    /// Env variable: `OTEL_METRIC_EXPORT_INTERVAL`
    pub fn set_metric_export_interval(&mut self, interval: u32) -> &mut Self {
        self.config.metric_export_interval.set_code(interval);
        self
    }

    /// Set the metric export timeout in milliseconds.
    ///
    /// **Default**: `7500`
    ///
    /// Env variable: `OTEL_METRIC_EXPORT_TIMEOUT`
    pub fn set_metric_export_timeout(&mut self, timeout: u32) -> &mut Self {
        self.config.metric_export_timeout.set_code(timeout);
        self
    }

    /// Sets the hostname for DogStatsD metric collection.
    ///
    /// **Default**: `localhost`
    ///
    /// Env variable: `DD_DOGSTATSD_HOST`
    pub fn set_dogstatsd_agent_host(&mut self, host: String) -> &mut Self {
        self.config
            .dogstatsd_agent_host
            .set_code(Cow::Owned(host.to_string()));
        self
    }

    /// Sets the port for DogStatsD metric collection.
    ///
    /// **Default**: `8125`
    ///
    /// Env variable: `DD_DOGSTATSD_PORT`
    pub fn set_dogstatsd_agent_port(&mut self, port: u32) -> &mut Self {
        self.config.dogstatsd_agent_port.set_code(port);
        self
    }

    /// Enable partial flushing of traces.
    ///
    /// **Default**: `false`
    ///
    /// Env variable: `DD_TRACE_PARTIAL_FLUSH_ENABLED`
    pub fn set_trace_partial_flush_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.trace_partial_flush_enabled.set_code(enabled);
        self
    }

    /// Minimum number of spans in a trace before partial flush is triggered.
    ///
    /// **Default**: `300`
    ///
    /// Env variable: `DD_TRACE_PARTIAL_FLUSH_MIN_SPANS`
    pub fn set_trace_partial_flush_min_spans(&mut self, min_spans: usize) -> &mut Self {
        self.config
            .trace_partial_flush_min_spans
            .set_code(min_spans);
        self
    }

    /// A JSON array of objects to apply for trace sampling. Each rule must have a `sample_rate`
    /// between 0.0 and 1.0 (inclusive).
    ///
    /// **Default**: `[]`
    ///
    /// Env variable: `DD_TRACE_SAMPLING_RULES`
    pub fn set_trace_sampling_rules(&mut self, rules: Vec<SamplingRuleConfig>) -> &mut Self {
        self.config
            .trace_sampling_rules
            .set_code(ParsedSamplingRules { rules });
        self
    }

    /// Maximum number of traces to sample per second.
    /// Only applied if trace_sampling_rules are matched
    ///
    /// **Default**: `100`
    ///
    /// Env variable: `DD_TRACE_RATE_LIMIT`
    pub fn set_trace_rate_limit(&mut self, rate_limit: i32) -> &mut Self {
        self.config.trace_rate_limit.set_code(rate_limit);
        self
    }

    /// Global trace sample rate. Applied as a catch-all sample rate when no
    /// explicit sampling rule matches.
    ///
    /// **Default**: `1.0`
    ///
    /// Env variable: `DD_TRACE_SAMPLE_RATE`
    pub fn set_trace_sample_rate(&mut self, rate: f64) -> &mut Self {
        // Only accept finite values in [0.0, 1.0]; an out-of-range value is
        // logged and left unset rather than installed as a catch-all rule.
        if let Some(rate) = validate_trace_sample_rate(rate) {
            self.config.trace_sample_rate.set_code(Some(rate));
        }
        self
    }

    /// A list of propagation styles to use for both extraction and injection. Supported values are
    /// `datadog` and `tracecontext`.
    ///
    /// **Default**: `[Datadog, TraceContext]`
    ///
    /// Env variable: `DD_TRACE_PROPAGATION_STYLE`
    pub fn set_trace_propagation_style(&mut self, styles: Vec<TracePropagationStyle>) -> &mut Self {
        self.config.trace_propagation_style.set_code(Some(styles));
        self
    }

    /// A list of propagation styles to use for extraction. When set, this overrides
    /// `DD_TRACE_PROPAGATION_STYLE` for extraction.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `DD_TRACE_PROPAGATION_STYLE_EXTRACT`
    pub fn set_trace_propagation_style_extract(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config
            .trace_propagation_style_extract
            .set_code(Some(styles));
        self
    }

    /// A list of propagation styles to use for injection. When set, this overrides
    /// `DD_TRACE_PROPAGATION_STYLE` for injection.
    ///
    /// **Default**: `(none)`
    ///
    /// Env variable: `DD_TRACE_PROPAGATION_STYLE_INJECT`
    pub fn set_trace_propagation_style_inject(
        &mut self,
        styles: Vec<TracePropagationStyle>,
    ) -> &mut Self {
        self.config
            .trace_propagation_style_inject
            .set_code(Some(styles));
        self
    }

    /// When set to `true`, stops extracting after the first successful trace context extraction.
    ///
    /// **Default**: `false`
    ///
    /// Env variable: `DD_TRACE_PROPAGATION_EXTRACT_FIRST`
    pub fn set_trace_propagation_extract_first(&mut self, first: bool) -> &mut Self {
        self.config.trace_propagation_extract_first.set_code(first);
        self
    }

    /// Controls which baggage keys are promoted to span tags with a `"baggage."` prefix.
    ///
    /// **Default**: `BaggageTagKeyFilter::Keys(["user.id", "session.id", "account.id"])`
    ///
    /// Env variable: `DD_TRACE_BAGGAGE_TAG_KEYS`
    pub fn set_trace_baggage_tag_keys(&mut self, filter: BaggageTagKeyFilter) -> &mut Self {
        self.config.trace_baggage_tag_keys.set_code(filter);
        self
    }

    /// Set to `false` to disable tracing.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_TRACE_ENABLED`
    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.enabled.set_code(enabled);
        self
    }

    /// Sets the internal log level for the tracer.
    ///
    /// **Default**: `Error`
    ///
    /// Env variable: `DD_LOG_LEVEL`
    pub fn set_log_level_filter(&mut self, filter: LevelFilter) -> &mut Self {
        self.config.log_level_filter.set_code(filter);
        self
    }

    /// Enable computation of trace statistics.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_TRACE_STATS_COMPUTATION_ENABLED`
    pub fn set_trace_stats_computation_enabled(
        &mut self,
        trace_stats_computation_enabled: bool,
    ) -> &mut Self {
        self.config
            .trace_stats_computation_enabled
            .set_code(trace_stats_computation_enabled);
        self
    }

    /// Enable or disable remote configuration.
    ///
    /// **Default**: `true`
    ///
    /// Env variable: `DD_REMOTE_CONFIGURATION_ENABLED`
    pub fn set_remote_config_enabled(&mut self, enabled: bool) -> &mut Self {
        self.config.remote_config_enabled.set_code(enabled);
        self
    }

    /// Interval in seconds for polling remote configuration updates.
    ///
    /// **Default**: `5.0`
    ///
    /// Env variable: `DD_REMOTE_CONFIG_POLL_INTERVAL_SECONDS`
    pub fn set_remote_config_poll_interval(&mut self, seconds: f64) -> &mut Self {
        self.config
            .remote_config_poll_interval
            .set_code(seconds.abs().min(RC_DEFAULT_POLL_INTERVAL));
        self
    }

    /// Maximum length of the `x-datadog-tags` header in bytes.
    ///
    /// **Default**: `512`
    ///
    /// Env variable: `DD_TRACE_X_DATADOG_TAGS_MAX_LENGTH`
    pub fn set_datadog_tags_max_length(&mut self, length: usize) -> &mut Self {
        self.config
            .datadog_tags_max_length
            .set_code(length.min(DATADOG_TAGS_MAX_LENGTH));
        self
    }

    /// Enable synchronous trace writes.
    ///
    /// When `true`, each trace export immediately triggers a flush and waits for the background
    /// exporter to process that batch. The wait is bounded by
    /// [`ConfigBuilder::set_trace_writer_synchronous_timeout`]; if that timeout is reached, the
    /// flush may continue in the background.
    ///
    /// Useful for short-lived processes such as AWS Lambda functions where the process may freeze
    /// before an async write completes, or in tests where reducing buffering improves determinism.
    ///
    /// **Default**: `false`
    pub fn set_trace_writer_synchronous_write(
        &mut self,
        trace_writer_synchronous_write: bool,
    ) -> &mut Self {
        self.config.trace_writer_synchronous_write = trace_writer_synchronous_write;
        self
    }

    /// Set the maximum time to wait for synchronous trace writes.
    ///
    /// This only applies when [`ConfigBuilder::set_trace_writer_synchronous_write`] is enabled.
    /// If the timeout is reached, the flush may continue in the background.
    ///
    /// **Default**: `2s`
    pub fn set_trace_writer_synchronous_timeout(
        &mut self,
        trace_writer_synchronous_timeout: Duration,
    ) -> &mut Self {
        self.config.trace_writer_synchronous_timeout = trace_writer_synchronous_timeout;
        self
    }

    #[cfg(feature = "test-utils")]
    #[allow(missing_docs)]
    pub fn set_datadog_tags_max_length_with_no_limit(&mut self, length: usize) -> &mut Self {
        self.config.datadog_tags_max_length.set_code(length);
        self
    }

    #[cfg(feature = "test-utils")]
    #[allow(missing_docs)]
    pub fn set_trace_writer_max_flush_interval(
        &mut self,
        trace_writer_max_flush_interval: Duration,
    ) -> &mut Self {
        self.config.trace_writer_max_flush_interval = trace_writer_max_flush_interval;
        self
    }

    #[cfg(feature = "test-utils")]
    pub(crate) fn __internal_set_wait_agent_info_ready(
        &mut self,
        wait_agent_info_ready: bool,
    ) -> &mut Self {
        self.config.wait_agent_info_ready = wait_agent_info_ready;
        self
    }
}

#[cfg(test)]
mod tests {
    use libdd_telemetry::data::ConfigurationOrigin;
    use std::collections::HashMap;

    use super::Config;
    use super::*;
    use crate::core::configuration::sources::{CompositeSource, ConfigSourceOrigin, HashMapSource};

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

        assert_eq!(&*config.service(), "test-service");
        assert_eq!(config.env(), Some("test-env"));
        assert_eq!(config.trace_rate_limit(), 123);
        let rules = config.trace_sampling_rules();
        assert_eq!(rules.len(), 1, "Should have one rule");
        assert_eq!(
            &rules[0],
            &SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("web-api".to_string()),
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
                TracePropagationStyle::Baggage,
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
    fn test_propagation_style_baggage_parsed_from_env() {
        // "baggage" is recognised as a valid style value (case-insensitive) in all three env vars.
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_TRACE_PROPAGATION_STYLE", "datadog,tracecontext,baggage"),
                ("DD_TRACE_PROPAGATION_STYLE_EXTRACT", "Baggage,datadog"),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "BAGGAGE,tracecontext"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(
            config.trace_propagation_style(),
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::Baggage,
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![
                TracePropagationStyle::Baggage,
                TracePropagationStyle::Datadog,
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![
                TracePropagationStyle::Baggage,
                TracePropagationStyle::TraceContext,
            ])
            .as_deref()
        );
    }

    #[test]
    fn test_propagation_style_b3_display() {
        assert_eq!(TracePropagationStyle::B3Multi.to_string(), "b3multi");
        assert_eq!(TracePropagationStyle::B3SingleHeader.to_string(), "b3");
    }

    #[test]
    fn test_propagation_style_b3_parsed_from_env() {
        // Both b3multi and b3 now parse from env (case-insensitive).
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                (
                    "DD_TRACE_PROPAGATION_STYLE",
                    "datadog,tracecontext,b3multi,b3",
                ),
                ("DD_TRACE_PROPAGATION_STYLE_EXTRACT", "B3Multi,B3"),
                ("DD_TRACE_PROPAGATION_STYLE_INJECT", "b3,b3multi"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(
            config.trace_propagation_style(),
            Some(vec![
                TracePropagationStyle::Datadog,
                TracePropagationStyle::TraceContext,
                TracePropagationStyle::B3Multi,
                TracePropagationStyle::B3SingleHeader,
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_extract(),
            Some(vec![
                TracePropagationStyle::B3Multi,
                TracePropagationStyle::B3SingleHeader,
            ])
            .as_deref()
        );
        assert_eq!(
            config.trace_propagation_style_inject(),
            Some(vec![
                TracePropagationStyle::B3SingleHeader,
                TracePropagationStyle::B3Multi,
            ])
            .as_deref()
        );
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

        config.add_extra_services(
            [
                // Add some extra services
                "service-1",
                "service-2",
                "service-3",
                // Should not add the main service
                "main-service",
                // Should not add duplicates
                "service-1",
            ]
            .into_iter(),
        );

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
        config.add_extra_services(["service-1", "service-2"].into_iter());

        // Should return empty since remote config is disabled
        let services = config.get_extra_services();
        assert_eq!(services.len(), 0);
    }

    #[test]
    fn test_extra_services_limit() {
        let config = Config::builder()
            .set_service("main-service".to_string())
            .build();

        config.add_extra_services((0..70).map(|i| format!("service-{i}")));

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

        // Track callback invocations — uses internal type to verify provenance preservation
        let callback_called = Arc::new(Mutex::new(false));
        let callback_rules = Arc::new(Mutex::new(Vec::<libdd_sampling::SamplingRuleConfig>::new()));

        let callback_called_clone = callback_called.clone();
        let callback_rules_clone = callback_rules.clone();

        config.set_sampling_rules_callback(move |update| {
            *callback_called_clone.lock().unwrap() = true;
            let RemoteConfigUpdate::SamplingRules(rules) = update;
            *callback_rules_clone.lock().unwrap() = rules.clone();
        });

        // Initially callback should not be called
        assert!(!*callback_called.lock().unwrap());
        assert!(callback_rules.lock().unwrap().is_empty());

        // Update rules from remote config with provenance "dynamic"
        let rules_json = r#"[{"sample_rate":0.5,"service":"test-service","provenance":"dynamic"}]"#;
        config
            .update_sampling_rules_from_remote(rules_json, None)
            .unwrap();

        // Callback should be called with the new rules, provenance preserved
        assert!(*callback_called.lock().unwrap());
        let received = callback_rules.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].sample_rate, 0.5);
        assert_eq!(received[0].service, Some("test-service".to_string()));
        assert_eq!(received[0].provenance, "dynamic");
        drop(received);

        // Test clearing rules
        *callback_called.lock().unwrap() = false;
        callback_rules.lock().unwrap().clear();

        config.clear_remote_sampling_rules(None);

        // Callback should be called with fallback rules (empty in this case since no env/code rules
        // set)
        assert!(*callback_called.lock().unwrap());
        assert!(callback_rules.lock().unwrap().is_empty());
    }

    #[test]
    fn test_clear_remote_rules_callback_has_local_provenance() {
        let config = Config::builder()
            .set_trace_sampling_rules(vec![SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("local-svc".to_string()),
                ..SamplingRuleConfig::default()
            }])
            .build();

        let callback_rules = Arc::new(Mutex::new(Vec::<libdd_sampling::SamplingRuleConfig>::new()));
        let clone = callback_rules.clone();
        config.set_sampling_rules_callback(move |update| {
            let RemoteConfigUpdate::SamplingRules(rules) = update;
            *clone.lock().unwrap() = rules.clone();
        });

        // Push remote rules then clear to trigger fallback
        config
            .update_sampling_rules_from_remote(
                r#"[{"sample_rate":0.9,"provenance":"dynamic"}]"#,
                None,
            )
            .unwrap();
        config.clear_remote_sampling_rules(None);

        // Fallback rules should have "local" provenance
        let received = callback_rules.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].sample_rate, 0.5);
        assert_eq!(received[0].provenance, "local");
    }

    #[test]
    fn test_clear_remote_rules_includes_env_rate_catch_all() {
        // When DD_TRACE_SAMPLE_RATE is set and the remote override is cleared,
        // the callback must receive [env_rules..., catch_all(env_rate)] so the
        // sampler applies the env rate to unmatched spans.
        let mut config_builder = Config::builder();
        config_builder.set_trace_sample_rate(0.25);
        config_builder.set_trace_sampling_rules(vec![SamplingRuleConfig {
            sample_rate: 0.5,
            name: Some("env_name".to_string()),
            ..SamplingRuleConfig::default()
        }]);
        let config = config_builder.build();

        let received = Arc::new(Mutex::new(Vec::<libdd_sampling::SamplingRuleConfig>::new()));
        let clone = received.clone();
        config.set_sampling_rules_callback(move |update| {
            let RemoteConfigUpdate::SamplingRules(rules) = update;
            *clone.lock().unwrap() = rules.clone();
        });

        // Install a remote override, then clear it.
        config
            .update_sampling_rules_from_remote(
                r#"[{"sample_rate":0.9,"provenance":"customer"}]"#,
                None,
            )
            .unwrap();
        config.clear_remote_sampling_rules(None);

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 2, "expected env rule + env catch-all");
        assert_eq!(got[0].sample_rate, 0.5);
        assert_eq!(got[0].name.as_deref(), Some("env_name"));
        assert_eq!(got[1].sample_rate, 0.25);
        assert!(got[1].name.is_none());
        assert!(got[1].service.is_none());
        // env catch-all carries "default" provenance (libdatadog's documented
        // default; maps to DM -3 in libdd-sampling).
        assert_eq!(got[1].provenance, "default");
    }

    #[test]
    fn test_public_sampling_rule_config_ignores_provenance_in_json() {
        // The public SamplingRuleConfig should silently ignore a "provenance" field in JSON,
        // since serde skips unknown fields by default.
        let json = r#"[{"sample_rate":0.5,"service":"svc","provenance":"dynamic"}]"#;
        let parsed: ParsedSamplingRules = json.parse().unwrap();
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].sample_rate, 0.5);
        assert_eq!(parsed.rules[0].service, Some("svc".to_string()));
        // No provenance field on the public type — it was silently dropped.

        // Round-trip: serialized output should NOT contain provenance
        let serialized = parsed.to_string();
        assert!(!serialized.contains("provenance"));
    }

    #[test]
    fn test_config_item_priority() {
        // Test that ConfigItem respects priority: remote_config > code > env_var > default
        let mut config_item = ConfigItemWithOverride::new_rc(
            SupportedConfigurations::DD_TRACE_SAMPLING_RULES,
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
            .update_sampling_rules_from_remote(remote_rules_json, None)
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
            .update_sampling_rules_from_remote(empty_remote_rules_json, None)
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
        config.clear_remote_sampling_rules(None);

        // Should remain on local rules
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.3);
        assert_eq!(
            config.trace_sampling_rules.source(),
            ConfigSourceOrigin::EnvVar
        );
    }

    #[test]
    fn test_update_sampling_rules_from_remote_config_id() {
        let config = Config::builder().build();

        let new_rules = vec![SamplingRuleConfig {
            sample_rate: 0.5,
            service: Some("test-service".to_string()),
            ..SamplingRuleConfig::default()
        }];

        let rules_json = serde_json::to_string(&new_rules).unwrap();
        config
            .update_sampling_rules_from_remote(&rules_json, Some("config_id_1".to_string()))
            .unwrap();

        assert_eq!(
            config.trace_sampling_rules.get_config_id(),
            Some("config_id_1".to_string())
        );

        config
            .update_sampling_rules_from_remote(&rules_json, Some("config_id_2".to_string()))
            .unwrap();
        assert_eq!(
            config.trace_sampling_rules.get_config_id(),
            Some("config_id_2".to_string())
        );

        config
            .update_sampling_rules_from_remote("[]", None)
            .unwrap();
        assert_eq!(config.trace_sampling_rules.get_config_id(), None);
    }

    #[test]
    fn test_local_trace_sampling_rules_bypasses_remote_override() {
        let config = Config::builder()
            .set_trace_sampling_rules(vec![SamplingRuleConfig {
                sample_rate: 0.5,
                name: Some("env_name".to_string()),
                ..SamplingRuleConfig::default()
            }])
            .build();

        // With no RC override, local == public.
        assert_eq!(config.local_trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules().len(), 1);

        // Set an RC override.
        config
            .update_sampling_rules_from_remote(
                r#"[{"sample_rate":0.9,"service":"svc","provenance":"customer"}]"#,
                None,
            )
            .unwrap();

        // The public accessor reflects the override; the local one still
        // returns the env-side value.
        assert_eq!(config.trace_sampling_rules().len(), 1);
        assert_eq!(config.trace_sampling_rules()[0].sample_rate, 0.9);

        let local = config.local_trace_sampling_rules();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].sample_rate, 0.5);
        assert_eq!(local[0].name.as_deref(), Some("env_name"));
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

        assert_eq!(&*config.trace_agent_url(), "http://localhost:8126");
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

        assert_eq!(&*config.trace_agent_url(), "http://agent-host:4242");
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

        assert_eq!(&*config.trace_agent_url(), "https://test-host");
    }

    #[test]
    fn test_dd_agent_url_from_url_empty() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_AGENT_HOST", "agent-host"),
                ("DD_TRACE_AGENT_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(&*config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_url_set_to_empty_string() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_AGENT_URL", "")],
            ConfigSourceOrigin::Calculated,
        ));
        sources.add_source(HashMapSource::from_iter(
            [
                ("DD_AGENT_HOST", "agent-host"),
                ("DD_TRACE_AGENT_PORT", "4242"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert_eq!(&*config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_host_and_port_using_builder() {
        let config = Config::builder()
            .set_agent_host("agent-host".into())
            .set_trace_agent_port(4242)
            .build();

        assert_eq!(&*config.trace_agent_url(), "http://agent-host:4242");
    }

    #[test]
    fn test_dd_agent_url_from_url_using_builder() {
        let config = Config::builder()
            .set_agent_host("agent-host".into())
            .set_trace_agent_port(4242)
            .set_trace_agent_url("https://test-host".into())
            .build();

        assert_eq!(&*config.trace_agent_url(), "https://test-host");
    }

    #[test]
    fn test_dogstatsd_agent_url_default() {
        let config = Config::builder().build();

        assert_eq!(&*config.dogstatsd_agent_url(), "http://localhost:8125");
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

        assert_eq!(&*config.dogstatsd_agent_url(), "http://dogstatsd-host:4242");
    }

    #[test]
    fn test_dogstatsd_agent_url_from_url_using_builder() {
        let config = Config::builder()
            .set_dogstatsd_agent_host("dogstatsd-host".into())
            .set_dogstatsd_agent_port(4242)
            .build();

        assert_eq!(&*config.dogstatsd_agent_url(), "http://dogstatsd-host:4242");
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

        let env = cisu.update_string(default.env, Some);
        assert_eq!(env.default_value, None);
        assert_eq!(env.env_value, Some(Some("test-env".to_string())));
        assert_eq!(env.code_value, None);

        let enabled = cisu.update_parsed(default.enabled);
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

        let tags = cisu.update_parsed_with_transform(default.global_tags, |Tags(tags)| tags);
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
            r#"[{"sample_rate":0.5,"service":"web-api","name":null,"resource":null,"tags":{}}]"#,
        )
        .unwrap();

        let configurations = &config.trace_sampling_rules.get_all_configurations();
        // active config is the one with highest seq_id
        let active_configuration = configurations.iter().max_by_key(|c| c.seq_id).unwrap();
        assert_eq!(active_configuration.origin, ConfigurationOrigin::EnvVar);

        // Converting configuration value to json helps with comparison as serialized properties may
        // differ from their original order
        assert_eq!(
            ParsedSamplingRules::from_str(&active_configuration.value).unwrap(),
            expected.clone()
        );

        // Update ConfigItemRc via RC
        let expected_rc = ParsedSamplingRules::from_str(
            r#"[{"sample_rate":1,"service":"web-api","name":null,"resource":null,"tags":{}}]"#,
        )
        .unwrap();
        config
            .trace_sampling_rules
            .set_override_value(expected_rc.clone(), ConfigSourceOrigin::RemoteConfig);

        let configurations_after_rc = &config.trace_sampling_rules.get_all_configurations();
        let active_configuration_after_rc = configurations_after_rc
            .iter()
            .max_by_key(|c| c.seq_id)
            .unwrap();
        assert_eq!(
            active_configuration_after_rc.origin,
            ConfigurationOrigin::RemoteConfig
        );
        assert_eq!(
            ParsedSamplingRules::from_str(&active_configuration_after_rc.value).unwrap(),
            expected_rc
        );

        // Reset ConfigItemRc RC previous value
        config.trace_sampling_rules.unset_override_value();

        let configurations = &config.trace_sampling_rules.get_all_configurations();
        let active_configuration = configurations.iter().max_by_key(|c| c.seq_id).unwrap();
        assert_eq!(active_configuration.origin, ConfigurationOrigin::EnvVar);
        assert_eq!(
            ParsedSamplingRules::from_str(&active_configuration.value).unwrap(),
            expected
        );
    }

    #[test]
    fn test_datadog_tags_max_length() {
        let config = Config::builder().set_datadog_tags_max_length(4242).build();

        assert_eq!(config.datadog_tags_max_length(), DATADOG_TAGS_MAX_LENGTH);

        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_X_DATADOG_TAGS_MAX_LENGTH", "4242")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert_eq!(config.datadog_tags_max_length(), DATADOG_TAGS_MAX_LENGTH);

        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_X_DATADOG_TAGS_MAX_LENGTH", "42")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert_eq!(config.datadog_tags_max_length(), 42);
    }

    #[test]
    fn test_remote_config_poll_interval() {
        let config = Config::builder()
            .set_remote_config_poll_interval(42.0)
            .build();

        assert_eq!(config.remote_config_poll_interval(), 5.0);

        let config = Config::builder()
            .set_remote_config_poll_interval(-0.2)
            .build();

        assert_eq!(config.remote_config_poll_interval(), 0.2);
    }

    #[test]
    fn test_trace_sample_rate_defaults_to_none_when_unset() {
        let config = Config::builder().build();
        assert_eq!(config.trace_sample_rate(), None);
    }

    #[test]
    fn test_trace_sample_rate_parses_from_env() {
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("DD_TRACE_SAMPLE_RATE", "0.25")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();
        assert_eq!(config.trace_sample_rate(), Some(0.25));
    }

    #[test]
    fn test_explicit_dd_trace_sample_rate_one_installs_catch_all() {
        // Codex MEDIUM fix: explicit DD_TRACE_SAMPLE_RATE=1.0 must install a
        // catch-all rule so the rate limiter applies. Unset is still distinct
        // (no catch-all, libdatadog's 100% fallback).
        let mut builder = Config::builder();
        builder.set_trace_sample_rate(1.0);
        let config = builder.build();

        let rules = config.effective_initial_rules();
        assert_eq!(rules.len(), 1, "explicit 1.0 must install a catch-all");
        assert_eq!(rules[0].sample_rate, 1.0);

        // Unset: no catch-all.
        let unset_config = Config::builder().build();
        let unset_rules = unset_config.effective_initial_rules();
        assert!(unset_rules.is_empty(), "unset must not install a catch-all");
    }

    #[test]
    fn test_out_of_range_dd_trace_sample_rate_env_is_treated_as_unset() {
        // Codex fix: a finite-but-out-of-range DD_TRACE_SAMPLE_RATE must be
        // rejected at ingestion (treated as unset), not installed as a
        // catch-all that libdd-sampling would clamp (negative -> drop all,
        // >1.0 -> keep all) while still enabling the rate limiter.
        for bad in ["1.5", "-0.5", "2", "inf", "-inf", "nan"] {
            let mut sources = CompositeSource::new();
            sources.add_source(HashMapSource::from_iter(
                [("DD_TRACE_SAMPLE_RATE", bad)],
                ConfigSourceOrigin::EnvVar,
            ));
            let config = Config::builder_with_sources(&sources).build();
            assert_eq!(
                config.trace_sample_rate(),
                None,
                "DD_TRACE_SAMPLE_RATE={bad} must be treated as unset"
            );
            assert!(
                config.effective_initial_rules().is_empty(),
                "DD_TRACE_SAMPLE_RATE={bad} must not install a catch-all rule"
            );
        }
    }

    #[test]
    fn test_in_range_boundary_dd_trace_sample_rate_env_accepted() {
        // Boundaries 0.0 and 1.0 are valid and must be accepted.
        for (val, expected) in [("0.0", 0.0), ("1.0", 1.0)] {
            let mut sources = CompositeSource::new();
            sources.add_source(HashMapSource::from_iter(
                [("DD_TRACE_SAMPLE_RATE", val)],
                ConfigSourceOrigin::EnvVar,
            ));
            let config = Config::builder_with_sources(&sources).build();
            assert_eq!(config.trace_sample_rate(), Some(expected));
        }
    }

    #[test]
    fn test_out_of_range_set_trace_sample_rate_is_ignored() {
        // The programmatic (code) setter must apply the same validation as the
        // env path: an out-of-range rate is ignored, leaving the rate unset.
        let mut builder = Config::builder();
        builder.set_trace_sample_rate(42.0);
        let config = builder.build();
        assert_eq!(config.trace_sample_rate(), None);
        assert!(config.effective_initial_rules().is_empty());

        // A valid rate is still accepted.
        let mut ok_builder = Config::builder();
        ok_builder.set_trace_sample_rate(0.3);
        assert_eq!(ok_builder.build().trace_sample_rate(), Some(0.3));
    }

    /// Collects every configuration entry reported via the telemetry
    /// configuration list, mirroring the app-started reporting path.
    fn collect_telemetry_configurations(config: &Config) -> Vec<Configuration> {
        config
            .get_telemetry_configuration()
            .into_iter()
            .flat_map(|provider| provider.get_all_configurations())
            .collect()
    }

    #[test]
    fn test_sensitive_otlp_headers_excluded_from_telemetry() {
        const SENTINEL_OTLP_BASE: &str = "dd-api-key=SENTINEL_OTLP_BASE";
        const SENTINEL_OTLP_METRICS: &str = "dd-api-key=SENTINEL_OTLP_METRICS";
        const SENTINEL_OTLP_LOGS: &str = "dd-api-key=SENTINEL_OTLP_LOGS";

        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [
                // Sensitive configurations, each with a distinct sentinel value.
                ("OTEL_EXPORTER_OTLP_HEADERS", SENTINEL_OTLP_BASE),
                ("OTEL_EXPORTER_OTLP_METRICS_HEADERS", SENTINEL_OTLP_METRICS),
                ("OTEL_EXPORTER_OTLP_LOGS_HEADERS", SENTINEL_OTLP_LOGS),
                // Non-sensitive exporter configurations that must still be reported.
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
                ("OTEL_EXPORTER_OTLP_TIMEOUT", "5000"),
            ],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        // The values are still parsed and usable; only their telemetry
        // reporting is suppressed.
        assert_eq!(config.otlp_headers(), SENTINEL_OTLP_BASE);
        assert_eq!(config.otlp_metrics_headers(), SENTINEL_OTLP_METRICS);
        assert_eq!(config.otlp_logs_headers(), SENTINEL_OTLP_LOGS);

        let configurations = collect_telemetry_configurations(&config);

        // No sentinel value may appear in any reported configuration value.
        for sentinel in [
            SENTINEL_OTLP_BASE,
            SENTINEL_OTLP_METRICS,
            SENTINEL_OTLP_LOGS,
        ] {
            assert!(
                !configurations.iter().any(|c| c.value.contains(sentinel)),
                "sentinel value {sentinel:?} must not appear in telemetry configuration"
            );
        }

        // Sensitive header configurations are omitted entirely (omit idiom).
        for name in [
            "OTEL_EXPORTER_OTLP_HEADERS",
            "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        ] {
            assert!(
                !configurations.iter().any(|c| c.name == name),
                "expected {name} to be absent from configuration telemetry"
            );
        }

        // Non-sensitive exporter configurations are still reported with their
        // real values.
        let value_for = |name: &str| {
            configurations
                .iter()
                .filter(|c| c.name == name)
                .max_by_key(|c| c.seq_id)
                .map(|c| c.value.clone())
        };
        assert_eq!(
            value_for("OTEL_EXPORTER_OTLP_ENDPOINT").as_deref(),
            Some("http://localhost:4318")
        );
        assert_eq!(
            value_for("OTEL_EXPORTER_OTLP_PROTOCOL").as_deref(),
            Some("http/protobuf")
        );
        assert_eq!(
            value_for("OTEL_EXPORTER_OTLP_TIMEOUT").as_deref(),
            Some("5000")
        );
    }

    #[test]
    fn test_sensitive_config_item_get_all_configurations_is_empty() {
        // The reusable mechanism applies at the ConfigItem level: a sensitive
        // configuration reports no telemetry entries regardless of source.
        let mut sources = CompositeSource::new();
        sources.add_source(HashMapSource::from_iter(
            [("OTEL_EXPORTER_OTLP_HEADERS", "dd-api-key=SENTINEL")],
            ConfigSourceOrigin::EnvVar,
        ));
        let config = Config::builder_with_sources(&sources).build();

        assert!(
            config.otlp_headers.get_all_configurations().is_empty(),
            "sensitive ConfigItem must not report any configuration entries"
        );

        // A non-sensitive ConfigItem continues to report entries.
        assert!(
            !config.otlp_endpoint.get_all_configurations().is_empty(),
            "non-sensitive ConfigItem should still report configuration entries"
        );
    }
}
