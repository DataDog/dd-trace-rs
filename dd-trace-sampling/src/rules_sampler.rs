// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::datadog_sampler::SamplingRule;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct SamplingRuleConfig {
    pub sample_rate: f64,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub tags: Option<HashMap<String, String>>,
    #[serde(default)]
    pub provenance: Option<String>,
}

/// Configuration for sampling rules as received from remote configuration
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SamplingRulesConfig {
    pub rules: Vec<SamplingRuleConfig>,
}

impl SamplingRulesConfig {
    /// Converts the configuration into a vector of SamplingRule instances
    pub fn into_rules(self) -> Vec<SamplingRule> {
        self.rules
            .into_iter()
            .map(|config| {
                SamplingRule::new(
                    config.sample_rate,
                    config.service,
                    config.name,
                    config.resource,
                    config.tags,
                    config.provenance,
                )
            })
            .collect()
    }
}

/// Thread-safe container for sampling rules
#[derive(Debug, Default, Clone)]
pub(crate) struct RulesSampler {
    inner: Arc<RwLock<Vec<SamplingRule>>>,
}

impl RulesSampler {
    /// Creates a new RulesSampler with the given initial rules
    pub fn new(rules: Vec<SamplingRule>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(rules)),
        }
    }

    /// Gets a clone of the current rules
    #[allow(dead_code)]
    pub fn get_rules(&self) -> Vec<SamplingRule> {
        self.inner.read().unwrap().clone()
    }

    /// Updates the rules with a new set
    pub fn update_rules(&self, new_rules: Vec<SamplingRule>) {
        *self.inner.write().unwrap() = new_rules;
    }

    /// Finds the first matching rule for a span
    pub fn find_matching_rule<F>(&self, matcher: F) -> Option<SamplingRule>
    where
        F: Fn(&SamplingRule) -> bool,
    {
        self.inner
            .read()
            .unwrap()
            .iter()
            .find(|rule| matcher(rule))
            .cloned()
    }

    // used for testing purposes
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}
