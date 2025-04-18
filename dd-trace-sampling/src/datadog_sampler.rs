// Copyright 2023-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::TraceId;
use opentelemetry::{Context, KeyValue, Value};
use opentelemetry::trace::{SamplingDecision, SamplingResult, Span, TraceContextExt};
use opentelemetry_sdk::trace::ShouldSample;
use std::collections::HashMap;
use serde_json;

use crate::constants::{SamplingMechanism, SamplingPriority, 
                       SAMPLING_DECISION_MAKER_TAG_KEY, SAMPLING_PRIORITY_TAG_KEY,
                       SAMPLING_RULE_RATE_TAG_KEY, SAMPLING_AGENT_RATE_TAG_KEY,
                       SAMPLING_MECHANISM_TO_PRIORITIES,
                       KEEP_PRIORITY_INDEX, REJECT_PRIORITY_INDEX};

use crate::rate_sampler::RateSampler;
use crate::glob_matcher::GlobMatcher;
use crate::config;

/// Constant to represent "no rule" for a field
pub const NO_RULE: &str = "";

/// Represents a sampling rule with criteria for matching spans
#[derive(Clone, Debug)]
pub struct SamplingRule {
    /// The sample rate to apply when this rule matches (0.0-1.0)
    pub sample_rate: f64,
    
    /// Optional service name to match (checked in span attributes for "service.name")
    pub service: Option<String>,
    
    /// Optional span name to match
    pub name: Option<String>,
    
    /// Optional resource name to match (checked in span attributes for "resource.name")
    pub resource: Option<String>,
    
    /// Key-value pairs that must all match in the span's attributes
    pub tags: HashMap<String, String>,
    
    /// Where this rule comes from (customer, dynamic, default)
    pub provenance: String,
    
    /// Internal rate sampler used when this rule matches
    rate_sampler: RateSampler,
    
    /// Glob matchers for pattern matching
    name_matcher: Option<GlobMatcher>,
    service_matcher: Option<GlobMatcher>,
    resource_matcher: Option<GlobMatcher>,
    tag_matchers: HashMap<String, GlobMatcher>,
}

impl SamplingRule {
    /// Creates a new sampling rule
    pub fn new(
        sample_rate: f64,
        service: Option<String>,
        name: Option<String>,
        resource: Option<String>,
        tags: Option<HashMap<String, String>>,
        provenance: Option<String>,
    ) -> Self {
        // Create glob matchers for the patterns
        let name_matcher = name.as_ref().and_then(|n| {
            if n != NO_RULE {
                Some(GlobMatcher::new(n))
            } else {
                None
            }
        });
        
        let service_matcher = service.as_ref().and_then(|s| {
            if s != NO_RULE {
                Some(GlobMatcher::new(s))
            } else {
                None
            }
        });
        
        let resource_matcher = resource.as_ref().and_then(|r| {
            if r != NO_RULE {
                Some(GlobMatcher::new(r))
            } else {
                None
            }
        });
        
        // Create matchers for tag values
        let tag_map = tags.clone().unwrap_or_default();
        let mut tag_matchers = HashMap::with_capacity(tag_map.len());
        for (key, value) in &tag_map {
            if value != NO_RULE {
                tag_matchers.insert(key.clone(), GlobMatcher::new(value));
            }
        }
        
        SamplingRule {
            sample_rate,
            service,
            name,
            resource,
            tags: tag_map,
            provenance: provenance.unwrap_or_else(|| "default".to_string()),
            rate_sampler: RateSampler::new(sample_rate),
            name_matcher,
            service_matcher,
            resource_matcher,
            tag_matchers,
        }
    }
    
    /// Extracts a string value from an OpenTelemetry Value
    fn extract_string_value(value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.to_string()),
            Value::I64(i) => Some(i.to_string()),
            Value::F64(f) => Some(f.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
    
    /// Checks if this rule matches the given span's attributes and name
    pub fn matches(&self, name: &str, attributes: &[KeyValue]) -> bool {
        // Check name using glob matcher if specified
        if let Some(ref matcher) = self.name_matcher {
            if !matcher.matches(name) {
                return false;
            }
        }
        
        // Convert attributes to a more easily searchable form
        let attr_map: HashMap<&str, String> = attributes
            .iter()
            .filter_map(|kv| {
                // Extract string value from attribute
                Self::extract_string_value(&kv.value)
                    .map(|val| (kv.key.as_str(), val))
            })
            .collect();
        
        // Check service if specified using glob matcher
        if let Some(ref matcher) = self.service_matcher {
            match attr_map.get("service.name") {
                Some(value) => {
                    if !matcher.matches(value) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        
        // Check resource if specified using glob matcher
        if let Some(ref matcher) = self.resource_matcher {
            match attr_map.get("resource.name") {
                Some(value) => {
                    if !matcher.matches(value) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        
        // Check all tags using glob matchers
        for (key, matcher) in &self.tag_matchers {
            match attr_map.get(key.as_str()) {
                Some(value) => {
                    if !matcher.matches(value) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        
        true
    }
    
    /// Samples a trace ID using this rule's sample rate
    pub fn sample(&self, trace_id: TraceId) -> bool {
        // Delegate to the internal rate sampler
        self.rate_sampler.should_sample(
            None,
            trace_id,
            "", // name not needed for rate sampler
            &opentelemetry::trace::SpanKind::Client,
            &[],
            &[],
        ).decision == SamplingDecision::RecordAndSample
    }
}

/// Represents a priority for sampling rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleProvenance {
    Customer = 0,
    Dynamic = 1,
    Default = 2,
}

impl From<&str> for RuleProvenance {
    fn from(s: &str) -> Self {
        match s {
            "customer" => RuleProvenance::Customer,
            "dynamic" => RuleProvenance::Dynamic,
            _ => RuleProvenance::Default,
        }
    }
}

/// Constants used by the Datadog sampler
pub const KNUTH_FACTOR: u64 = 1_111_111_111_111_111_111;
pub const SERVICE_TAG: &str = "service.name";
pub const ENV_TAG: &str = "env";

/// A composite sampler that applies rules in order of precedence
#[derive(Clone, Debug)]
pub struct DatadogSampler {
    /// Sampling rules to apply, in order of precedence
    rules: Vec<SamplingRule>,
    
    /// Service-based samplers provided by the Agent
    service_samplers: HashMap<String, RateSampler>,
    
    // Optional rate limiter (not implemented in this sketch)
    // rate_limiter: Option<RateLimiter>,
}

impl DatadogSampler {
    /// Creates a new DatadogSampler with the given rules
    pub fn new(
        rules: Option<Vec<SamplingRule>>,
        _rate_limit: Option<u32>,
    ) -> Self {
        // Sort rules by provenance if provided
        let sorted_rules = if let Some(mut r) = rules {
            r.sort_by_key(|rule| RuleProvenance::from(rule.provenance.as_str()));
            r
        } else {
            Vec::new()
        };
        
        DatadogSampler {
            rules: sorted_rules,
            service_samplers: HashMap::new(),
            // rate_limiter: rate_limit.map(|limit| RateLimiter::new(limit as u64)),
        }
    }
    
    /// Creates a new DatadogSampler from a JSON configuration string
    pub fn from_json(config_json: &str) -> Result<Self, serde_json::Error> {
        // Parse the JSON config
        let config = crate::config::DatadogSamplerConfig::from_json(config_json)?;
        
        // Build the sampler from the config
        Ok(config.build_sampler())
    }
    
    /// Computes a key for service-based sampling
    fn service_key(&self, attributes: &[KeyValue]) -> String {
        let mut service = String::new();
        let mut env = String::new();
        
        for attr in attributes {
            if attr.key.as_str() == SERVICE_TAG {
                if let Some(val) = SamplingRule::extract_string_value(&attr.value) {
                    service = val;
                }
            } else if attr.key.as_str() == ENV_TAG {
                if let Some(val) = SamplingRule::extract_string_value(&attr.value) {
                    env = val;
                }
            }
        }
        
        format!("service:{},env:{}", service, env)
    }
    
    /// Updates the service-based sample rates from the Agent
    pub fn update_service_rates(&mut self, rates: HashMap<String, f64>) {
        let mut samplers = HashMap::new();
        for (key, rate) in rates {
            samplers.insert(key, RateSampler::new(rate));
        }
        self.service_samplers = samplers;
    }
    
    /// Finds the highest precedence rule that matches the span
    fn find_matching_rule(&self, name: &str, attributes: &[KeyValue]) -> Option<&SamplingRule> {
        self.rules.iter().find(|rule| rule.matches(name, attributes))
    }
    
    /// Returns the sampling mechanism used for the decision 
    fn get_sampling_mechanism(&self, rule: Option<&SamplingRule>, used_agent_sampler: bool) -> SamplingMechanism {
        if let Some(rule) = rule {
            match rule.provenance.as_str() {
                // Provenance will not be set for rules until we implement remote configuration
                "customer" => SamplingMechanism::RemoteUserTraceSamplingRule,
                "dynamic" => SamplingMechanism::RemoteDynamicTraceSamplingRule,
                _ => SamplingMechanism::LocalUserTraceSamplingRule,
            }
        } else if used_agent_sampler {
            // If using service-based sampling from the agent
            SamplingMechanism::AgentRateByService 
        } else {
            // Should not happen, but just in case
            SamplingMechanism::Default
        }
    }
    
    /// Adds Datadog-specific sampling tags to the attributes
    /// 
    /// # Parameters
    /// * `decision` - The sampling decision (RecordAndSample or Drop)
    /// * `mechanism` - The sampling mechanism used to make the decision
    /// * `sample_rate` - The sample rate to use for the decision
    /// 
    /// # Returns
    /// A vector of attributes to add to the sampling result
    fn add_dd_sampling_tags(
        &self,
        decision: &SamplingDecision,
        mechanism: SamplingMechanism,
        sample_rate: f64,
    ) -> Vec<KeyValue> {
        let mut result = Vec::new();
        
        // Add the sampling decision trace tag with the mechanism
        result.push(KeyValue::new(
            SAMPLING_DECISION_MAKER_TAG_KEY,
            format!("-{}", mechanism.value())
        ));
        
        // Determine which priority index to use based on the decision
        let priority_index = if *decision == SamplingDecision::RecordAndSample {
            KEEP_PRIORITY_INDEX
        } else {
            REJECT_PRIORITY_INDEX
        };

        // Get the appropriate sampling priority value based on the mechanism and priority index
        let priority_pair = SAMPLING_MECHANISM_TO_PRIORITIES.get(&mechanism).unwrap();
        let priority = if priority_index == KEEP_PRIORITY_INDEX {
            priority_pair.0
        } else {
            priority_pair.1
        };

        result.push(KeyValue::new(
            SAMPLING_PRIORITY_TAG_KEY, 
            priority.value() as i64
        ));

        // Add the sample rate tag with the correct key based on the mechanism
        match mechanism {
            SamplingMechanism::AgentRateByService => {
                result.push(KeyValue::new(SAMPLING_AGENT_RATE_TAG_KEY, sample_rate));
            },
            SamplingMechanism::RemoteUserTraceSamplingRule | 
            SamplingMechanism::RemoteDynamicTraceSamplingRule | 
            SamplingMechanism::LocalUserTraceSamplingRule => {
                result.push(KeyValue::new(SAMPLING_RULE_RATE_TAG_KEY, sample_rate));
            },
            _ => {}
        }
        
        result
    }
}

impl ShouldSample for DatadogSampler {
    fn should_sample(
        &self,
        parent_context: Option<&Context>,
        trace_id: TraceId,
        name: &str,
        _span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[KeyValue],
        _links: &[opentelemetry::trace::Link],
    ) -> SamplingResult {
        // Check if there is a parent span context and if it has an active span
        if let Some(parent_ctx) = parent_context.filter(|cx| cx.has_active_span()) {
            // If a parent exists, inherit its sampling decision and trace state
            let span = parent_ctx.span();
            let parent_span_context = span.span_context();
            let decision = if parent_span_context.is_sampled() {
                SamplingDecision::RecordAndSample
            } else {
                SamplingDecision::Drop
            };
            
            return SamplingResult {
                decision,
                attributes: Vec::new(), // Attributes are not modified by this sampler for inherited decisions
                trace_state: parent_span_context.trace_state().clone(),
            };
        }
        
        // Apply rules-based sampling
        let mut decision = SamplingDecision::RecordAndSample;
        
        // Find a matching rule
        let matching_rule = self.find_matching_rule(name, attributes);
        
        // Track which sampling mechanism was used
        let mut used_agent_sampler = false;
        
        // Store the sample rate to use
        let sample_rate;
        
        // Apply sampling logic
        if let Some(rule) = matching_rule {
            // Get the sample rate from the rule
            sample_rate = rule.sample_rate;
            
            // Rule-based sampling
            if !rule.sample(trace_id) {
                decision = SamplingDecision::Drop;
            }
        } else {
            // Try service-based sampling from Agent
            let service_key = self.service_key(attributes);
            if let Some(sampler) = self.service_samplers.get(&service_key) {
                // Use the service-based sampler
                used_agent_sampler = true;
                sample_rate = sampler.sample_rate();
                
                let result = sampler.should_sample(None, trace_id, "", &opentelemetry::trace::SpanKind::Client, &[], &[]);
                if result.decision == SamplingDecision::Drop {
                    decision = SamplingDecision::Drop;
                }
            } else {
                // Default sample rate, should never happen
                sample_rate = 1.0;
                // Keep the default (RecordAndSample)
            }
        }
        
        // Determine the sampling mechanism
        let mechanism = self.get_sampling_mechanism(matching_rule, used_agent_sampler);
        
        // Add Datadog-specific sampling tags
        let result_attributes = self.add_dd_sampling_tags(&decision, mechanism, sample_rate);
        
        SamplingResult {
            decision,
            attributes: result_attributes,
            trace_state: Default::default(),
        }
    }
}
