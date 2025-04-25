// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use crate::datadog_sampler::{DatadogSampler, SamplingRule};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for a single sampling rule
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default = "default_provenance")]
    pub provenance: String,
}

fn default_provenance() -> String {
    "default".to_string()
}

/// Configuration for the DatadogSampler
///
/// This is an internal representation used for JSON (de)serialization.
/// **Note**: Users should not create or interact with DatadogSampler or SamplingRule instances directly.
///
/// Sampling rules can be configured via the environment variable `DD_TRACE_SAMPLING_RULES`,
/// which should contain a JSON string with the sampling rules configuration.
///
/// The tracer's initialization process automatically handles creating the appropriate sampler
/// based on these configuration settings.
///
/// # Example JSON Configuration for DD_TRACE_SAMPLING_RULES
/// ```json
/// {
///   "rules": [
///     {
///       "sample_rate": 1.0,
///       "service": "critical-service",
///       "name": "important-endpoint"
///     },
///     {
///       "sample_rate": 0.5,
///       "service": "web-*"
///     },
///     {
///       "sample_rate": 0.1,
///       "tags": {
///         "env": "staging"
///       }
///     }
///   ],
///   "rate_limit": 100
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatadogSamplerConfig {
    /// Sampling rules to use
    #[serde(default)]
    pub rules: Vec<SamplingRuleConfig>,

    /// Rate limit for sampling (samples/second)
    #[serde(default)]
    pub rate_limit: Option<i32>,
}

impl Default for DatadogSamplerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl DatadogSamplerConfig {
    /// Creates a new empty configuration
    pub fn new() -> Self {
        DatadogSamplerConfig {
            rules: Vec::new(),
            rate_limit: None,
        }
    }

    /// Create a new sampling configuration with the specified rules
    pub fn with_rules(rules: Vec<SamplingRuleConfig>) -> Self {
        DatadogSamplerConfig {
            rules,
            rate_limit: None,
        }
    }

    /// Create a new sampling configuration with all parameters
    pub fn with_config(rules: Vec<SamplingRuleConfig>, rate_limit: Option<i32>) -> Self {
        DatadogSamplerConfig { rules, rate_limit }
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Create a DatadogSampler from this configuration
    pub fn build_sampler(&self) -> DatadogSampler {
        // Convert the rule configs to actual SamplingRule instances
        let rules = self
            .rules
            .iter()
            .map(|config| {
                SamplingRule::new(
                    config.sample_rate,
                    config.service.clone(),
                    config.name.clone(),
                    config.resource.clone(),
                    Some(config.tags.clone()),
                    Some(config.provenance.clone()),
                )
            })
            .collect();

        DatadogSampler::new(Some(rules), self.rate_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_config() {
        let json = r#"
        {
            "rules": [
                {
                    "sample_rate": 0.5,
                    "service": "web-api",
                    "name": "http.request",
                    "provenance": "customer"
                },
                {
                    "sample_rate": 0.1,
                    "tags": {
                        "env": "production"
                    }
                }
            ],
            "rate_limit": 100
        }
        "#;

        let config = DatadogSamplerConfig::from_json(json).unwrap();
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].sample_rate, 0.5);
        assert_eq!(config.rules[0].service, Some("web-api".to_string()));
        assert_eq!(config.rules[0].provenance, "customer");
        assert_eq!(config.rules[1].sample_rate, 0.1);
        assert_eq!(
            config.rules[1].tags.get("env"),
            Some(&"production".to_string())
        );
        assert_eq!(config.rate_limit, Some(100));
    }
}
