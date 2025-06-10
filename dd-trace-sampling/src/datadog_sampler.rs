// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::constants::{
    RL_EFFECTIVE_RATE, SAMPLING_AGENT_RATE_TAG_KEY, SAMPLING_DECISION_MAKER_TAG_KEY,
    SAMPLING_PRIORITY_TAG_KEY, SAMPLING_RULE_RATE_TAG_KEY,
};
use dd_trace::sampling::{mechanism, SamplingDecision as DdSamplingDecision, SamplingMechanism};

use opentelemetry::trace::SamplingDecision;
use opentelemetry::trace::TraceId;
use opentelemetry::KeyValue;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Import the attr constants
use crate::constants::{attr::ENV_TAG, pattern::NO_RULE};
use crate::glob_matcher::GlobMatcher;
use crate::otel_utils::get_dd_key_for_otlp_attribute;
use crate::otel_utils::get_otel_operation_name_v2;
use crate::otel_utils::get_otel_resource_v2;
use crate::otel_utils::get_otel_service;
use crate::otel_utils::get_otel_status_code;
use crate::rate_limiter::RateLimiter;
use crate::rate_sampler::RateSampler;
use crate::sem_convs;
use crate::utils;

/// A trait to handle access to a Resource, whether it's a direct reference or wrapped in
/// Arc<RwLock<>>
pub trait ResourceAccess {
    fn get_resource(&self) -> opentelemetry_sdk::Resource;
}

impl ResourceAccess for opentelemetry_sdk::Resource {
    fn get_resource(&self) -> opentelemetry_sdk::Resource {
        self.clone()
    }
}

impl ResourceAccess for Arc<RwLock<opentelemetry_sdk::Resource>> {
    fn get_resource(&self) -> opentelemetry_sdk::Resource {
        // Clone the resource to avoid borrowing issues
        if let Ok(resource_guard) = self.read() {
            resource_guard.clone()
        } else {
            // Default empty resource if we can't acquire the lock
            opentelemetry_sdk::Resource::builder().build()
        }
    }
}

fn matcher_from_rule(rule: &str) -> Option<GlobMatcher> {
    (rule != NO_RULE).then(|| GlobMatcher::new(rule))
}

/// Represents a sampling rule with criteria for matching spans
#[derive(Clone, Debug)]
pub struct SamplingRule {
    /// The sample rate to apply when this rule matches (0.0-1.0)
    sample_rate: f64,

    /// Where this rule comes from (customer, dynamic, default)
    provenance: String,

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
        let name_matcher = name.as_deref().and_then(matcher_from_rule);
        let service_matcher = service.as_deref().and_then(matcher_from_rule);
        let resource_matcher = resource.as_deref().and_then(matcher_from_rule);

        // Create matchers for tag values
        let tag_map = tags.clone().unwrap_or_default();
        let mut tag_matchers = HashMap::with_capacity(tag_map.len());
        for (key, value) in &tag_map {
            if let Some(matcher) = matcher_from_rule(value) {
                tag_matchers.insert(key.clone(), matcher);
            }
        }

        SamplingRule {
            sample_rate,
            provenance: provenance.unwrap_or_else(|| "default".to_string()),
            rate_sampler: RateSampler::new(sample_rate),
            name_matcher,
            service_matcher,
            resource_matcher,
            tag_matchers,
        }
    }

    /// Checks if this rule matches the given span's attributes and name
    /// The name is derived from the attributes and span kind
    pub fn matches<R: ResourceAccess>(
        &self,
        attributes: &[KeyValue],
        span_kind: &opentelemetry::trace::SpanKind,
        resource: &R,
    ) -> bool {
        // Get the operation name from the attributes and span kind
        let name: std::borrow::Cow<'_, str> = get_otel_operation_name_v2(attributes, span_kind);

        // Check name using glob matcher if specified
        if let Some(ref matcher) = self.name_matcher {
            if !matcher.matches(name.as_ref()) {
                return false;
            }
        }

        // Get resource once for all checks
        let resource_instance = resource.get_resource();

        // Check service if specified using glob matcher
        if let Some(ref matcher) = self.service_matcher {
            // Get service directly from the resource
            let service_from_resource = get_otel_service(&resource_instance);

            // Match against the service from resource
            if !matcher.matches(&service_from_resource) {
                return false;
            }
        }

        // Get the resource string for matching
        let resource_str: std::borrow::Cow<'_, str> = get_otel_resource_v2(
            attributes,
            name.clone(),
            span_kind.clone(),
            &resource_instance,
        );

        // Check resource if specified using glob matcher
        if let Some(ref matcher) = self.resource_matcher {
            // Use the resource generated by get_otel_resource_v2
            if !matcher.matches(resource_str.as_ref()) {
                return false;
            }
        }

        // Check all tags using glob matchers
        for (key, matcher) in &self.tag_matchers {
            let rule_tag_key_str = key.as_str();

            // Special handling for rules defined with "http.status_code" or
            // "http.response.status_code"
            if rule_tag_key_str == sem_convs::ATTRIBUTE_HTTP_STATUS_CODE
                || rule_tag_key_str == sem_convs::ATTRIBUTE_HTTP_RESPONSE_STATUS_CODE
            {
                match self.match_http_status_code_rule(matcher, attributes) {
                    Some(true) => continue,             // Status code matched
                    Some(false) | None => return false, // Status code didn't match or wasn't found
                }
            } else {
                // Logic for other tags:
                // First, try to match directly with the provided tag key
                let direct_match = attributes
                    .iter()
                    .find(|kv| kv.key.as_str() == rule_tag_key_str)
                    .and_then(|kv| self.match_attribute_value(&kv.value, matcher));

                if direct_match.unwrap_or(false) {
                    continue;
                }

                // If no direct match, try to find the corresponding OpenTelemetry attribute that
                // maps to the Datadog tag key This handles cases where the rule key
                // is a Datadog key (e.g., "http.method") and the attribute is an
                // OTel key (e.g., "http.request.method")
                if rule_tag_key_str.starts_with("http.") {
                    let tag_match = attributes.iter().any(|kv| {
                        let dd_key_from_otel_attr = get_dd_key_for_otlp_attribute(kv.key.as_str());
                        if dd_key_from_otel_attr.as_ref() == rule_tag_key_str {
                            return self
                                .match_attribute_value(&kv.value, matcher)
                                .unwrap_or(false);
                        }
                        false
                    });

                    if !tag_match {
                        return false; // Mapped attribute not found or did not match
                    }
                    // If tag_match is true, loop continues to next rule_tag_key.
                } else {
                    // For non-HTTP attributes, if we don't have a direct match, the rule doesn't
                    // match
                    return false;
                }
            }
        }

        true
    }

    /// Helper method to specifically match a rule against an HTTP status code extracted from
    /// attributes. Returns Some(true) if status code found and matches, Some(false) if found
    /// but not matched, None if not found.
    fn match_http_status_code_rule(
        &self,
        matcher: &GlobMatcher,
        attributes: &[KeyValue],
    ) -> Option<bool> {
        let status_code_u32 = get_otel_status_code(attributes);
        if status_code_u32 != 0 {
            // Assuming 0 means not found
            let status_value = opentelemetry::Value::I64(i64::from(status_code_u32));
            self.match_attribute_value(&status_value, matcher)
        } else {
            None // Status code not found in attributes
        }
    }

    // Helper method to match attribute values considering different value types
    fn match_attribute_value(
        &self,
        value: &opentelemetry::Value,
        matcher: &GlobMatcher,
    ) -> Option<bool> {
        // Floating point values are handled with special rules
        if let Some(float_val) = utils::extract_float_value(value) {
            // Check if the float has a non-zero decimal part
            let has_decimal = float_val != (float_val as i64) as f64;

            // For non-integer floats, only match if it's a wildcard pattern
            if has_decimal {
                // All '*' pattern returns true, any other pattern returns false
                return Some(matcher.pattern().chars().all(|c| c == '*'));
            }

            // For integer floats, convert to string for matching
            return Some(matcher.matches(&float_val.to_string()));
        }

        // For non-float values, use normal matching
        utils::extract_string_value(value).map(|string_value| matcher.matches(&string_value))
    }

    /// Samples a trace ID using this rule's sample rate
    pub fn sample(&self, trace_id: TraceId) -> bool {
        // Delegate to the internal rate sampler's new sample method
        self.rate_sampler.sample(trace_id)
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

/// A composite sampler that applies rules in order of precedence
#[derive(Clone, Debug)]
pub struct DatadogSampler {
    /// Sampling rules to apply, in order of precedence
    rules: Vec<SamplingRule>,

    /// Service-based samplers provided by the Agent
    service_samplers: HashMap<String, RateSampler>,

    /// Rate limiter for limiting the number of spans per second
    rate_limiter: RateLimiter,

    /// Resource with service information, wrapped in Arc<RwLock<>> for sharing
    resource: Arc<RwLock<opentelemetry_sdk::Resource>>,
}

impl DatadogSampler {
    /// Creates a new DatadogSampler with the given rules
    pub fn new(
        rules: Vec<SamplingRule>,
        rate_limit: i32,
        resource: Arc<RwLock<opentelemetry_sdk::Resource>>,
    ) -> Self {
        // Create rate limiter with default value of 100 if not provided
        let limiter = RateLimiter::new(rate_limit, None);

        DatadogSampler {
            rules,
            service_samplers: HashMap::new(),
            rate_limiter: limiter,
            resource,
        }
    }

    /// Computes a key for service-based sampling
    fn service_key(&self, attributes: &[KeyValue]) -> String {
        // Get service directly from resource
        let resource_guard = self.resource.read().unwrap();
        let service = get_otel_service(&resource_guard).into_owned();

        // Get env from attributes
        let mut env = String::new();
        for attr in attributes {
            if attr.key.as_str() == ENV_TAG {
                if let Some(val) = utils::extract_string_value(&attr.value) {
                    env = val;
                    break;
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
    fn find_matching_rule(
        &self,
        attributes: &[KeyValue],
        span_kind: &opentelemetry::trace::SpanKind,
    ) -> Option<&SamplingRule> {
        // Create a copy of our resource for rule matching
        let resource = if let Ok(resource_guard) = self.resource.read() {
            resource_guard.clone()
        } else {
            // Default empty resource if we can't acquire the lock
            opentelemetry_sdk::Resource::builder().build()
        };

        self.rules
            .iter()
            .find(|rule| rule.matches(attributes, span_kind, &resource))
    }

    /// Returns the sampling mechanism used for the decision
    fn get_sampling_mechanism(
        &self,
        rule: Option<&SamplingRule>,
        used_agent_sampler: bool,
    ) -> SamplingMechanism {
        if let Some(rule) = rule {
            match rule.provenance.as_str() {
                // Provenance will not be set for rules until we implement remote configuration
                "customer" => mechanism::REMOTE_USER_TRACE_SAMPLING_RULE,
                "dynamic" => mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE,
                _ => mechanism::LOCAL_USER_TRACE_SAMPLING_RULE,
            }
        } else if used_agent_sampler {
            // If using service-based sampling from the agent
            mechanism::AGENT_RATE_BY_SERVICE
        } else {
            // Should not happen, but just in case
            mechanism::DEFAULT
        }
    }

    /// Sample an incoming span based on the parent context and attributes
    pub fn sample(
        &self,
        is_parent_sampled: Option<bool>,
        trace_id: TraceId,
        _name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[KeyValue],
    ) -> DdSamplingResult {
        if let Some(is_parent_sampled) = is_parent_sampled {
            // If a parent exists, inherit its sampling decision and trace state
            return DdSamplingResult {
                is_keep: is_parent_sampled,
                trace_root_info: None,
            };
        }

        // Apply rules-based sampling
        self.sample_root(trace_id, _name, span_kind, attributes)
    }

    /// Sample the root span of a trace
    fn sample_root(
        &self,
        trace_id: TraceId,
        _name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[KeyValue],
    ) -> DdSamplingResult {
        let mut is_keep = true;
        let mut used_agent_sampler = false;
        let sample_rate;
        let mut rl_effective_rate: Option<i32> = None;

        // Find a matching rule
        let matching_rule = self.find_matching_rule(attributes, span_kind);

        // Apply sampling logic
        if let Some(rule) = matching_rule {
            // Get the sample rate from the rule
            sample_rate = rule.sample_rate;

            // First check if the span should be sampled according to the rule
            if !rule.sample(trace_id) {
                is_keep = false;
            // If the span should be sampled, then apply rate limiting
            } else if !self.rate_limiter.is_allowed() {
                is_keep = false;
                rl_effective_rate = Some(self.rate_limiter.effective_rate() as i32);
            }
        } else {
            // Try service-based sampling from Agent
            let service_key = self.service_key(attributes);
            if let Some(sampler) = self.service_samplers.get(&service_key) {
                // Use the service-based sampler
                used_agent_sampler = true;
                sample_rate = sampler.sample_rate(); // Get rate for reporting

                // Check if the service sampler decides to drop
                if !sampler.sample(trace_id) {
                    is_keep = false;
                }
            } else {
                // Default sample rate, should never happen in practice if agent provides rates
                sample_rate = 1.0;
                // Keep the default decision (RecordAndSample)
            }
        }

        // Determine the sampling mechanism
        let mechanism = self.get_sampling_mechanism(matching_rule, used_agent_sampler);

        DdSamplingResult {
            is_keep,
            trace_root_info: Some(TraceRootSamplingInfo {
                decision: DdSamplingDecision {
                    mechanism,
                    priority: mechanism.to_priority(is_keep),
                },
                rate: sample_rate,
                rl_effective_rate,
            }),
        }
    }
}

pub struct DdSamplingResult {
    pub is_keep: bool,
    pub trace_root_info: Option<TraceRootSamplingInfo>,
}

pub struct TraceRootSamplingInfo {
    pub decision: DdSamplingDecision,
    pub rate: f64,
    pub rl_effective_rate: Option<i32>,
}

impl DdSamplingResult {
    /// Returns Datadog-specific sampling tags to be added as attributes
    ///
    /// # Parameters
    /// * `decision` - The sampling decision (RecordAndSample or Drop)
    /// * `mechanism` - The sampling mechanism used to make the decision
    /// * `sample_rate` - The sample rate to use for the decision
    /// * `rl_effective_rate` - The effective rate limit if rate limiting was applied
    ///
    /// # Returns
    /// A vector of attributes to add to the sampling result
    pub fn to_dd_sampling_tags(&self) -> Vec<KeyValue> {
        let mut result = Vec::new();
        let Some(root_info) = &self.trace_root_info else {
            return result; // No root info, return empty attributes
        };

        // Add rate limiting tag if applicable
        if let Some(limit) = root_info.rl_effective_rate {
            result.push(KeyValue::new(RL_EFFECTIVE_RATE, limit as i64));
        }

        // Add the sampling decision trace tag with the mechanism
        result.push(KeyValue::new(
            SAMPLING_DECISION_MAKER_TAG_KEY,
            root_info.decision.mechanism.to_cow(),
        ));

        result.push(KeyValue::new(
            SAMPLING_PRIORITY_TAG_KEY,
            root_info.decision.priority.into_i8() as i64,
        ));

        // Add the sample rate tag with the correct key based on the mechanism
        match root_info.decision.mechanism {
            mechanism::AGENT_RATE_BY_SERVICE => {
                result.push(KeyValue::new(SAMPLING_AGENT_RATE_TAG_KEY, root_info.rate));
            }
            mechanism::REMOTE_USER_TRACE_SAMPLING_RULE
            | mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE
            | mechanism::LOCAL_USER_TRACE_SAMPLING_RULE => {
                result.push(KeyValue::new(SAMPLING_RULE_RATE_TAG_KEY, root_info.rate));
            }
            _ => {}
        }

        result
    }

    /// Converts the sampling result to a SamplingResult for OpenTelemetry
    pub fn to_otel_decision(&self) -> SamplingDecision {
        if self.is_keep {
            SamplingDecision::RecordAndSample
        } else {
            SamplingDecision::RecordOnly
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute_keys::{
        DB_SYSTEM, HTTP_METHOD, MESSAGING_OPERATION, MESSAGING_SYSTEM, NETWORK_PROTOCOL_NAME,
    };
    use crate::constants::attr::{ENV_TAG, RESOURCE_TAG};
    use crate::constants::pattern;
    use opentelemetry::trace::SpanKind;
    use opentelemetry::{Key, KeyValue, Value};
    use opentelemetry_sdk::Resource as SdkResource;
    use opentelemetry_semantic_conventions as semconv;

    fn create_empty_resource_for_matching() -> opentelemetry_sdk::Resource {
        opentelemetry_sdk::Resource::builder().build()
    }

    // Helper function to create an empty resource wrapped in Arc<RwLock> for DatadogSampler
    fn create_empty_resource() -> Arc<RwLock<opentelemetry_sdk::Resource>> {
        Arc::new(RwLock::new(opentelemetry_sdk::Resource::builder().build()))
    }

    fn create_resource(res: String) -> Arc<RwLock<SdkResource>> {
        let attributes = vec![
            KeyValue::new(semconv::resource::SERVICE_NAME, res), // String `res` is Into<Value>
        ];
        let resource: SdkResource = SdkResource::builder().with_attributes(attributes).build();
        Arc::new(RwLock::new(resource))
    }

    // Helper function to create a trace ID
    fn create_trace_id() -> TraceId {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        TraceId::from_bytes(bytes)
    }

    // Helper function to create attributes for testing
    fn create_attributes(resource: &'static str, env: &'static str) -> Vec<KeyValue> {
        vec![
            KeyValue::new(RESOURCE_TAG, resource),
            KeyValue::new(ENV_TAG, env),
        ]
    }

    #[test]
    fn test_sampling_rule_creation() {
        let rule = SamplingRule::new(
            0.5,
            Some("test-service".to_string()),
            Some("test-name".to_string()),
            Some("test-resource".to_string()),
            Some(HashMap::from([(
                "custom-tag".to_string(),
                "tag-value".to_string(),
            )])),
            Some("customer".to_string()),
        );

        assert_eq!(rule.sample_rate, 0.5);
        assert_eq!(rule.service_matcher.unwrap().pattern(), "test-service");
        assert_eq!(rule.name_matcher.unwrap().pattern(), "test-name");
        assert_eq!(
            rule.resource_matcher.unwrap().pattern(),
            "test-resource".to_string()
        );
        assert_eq!(
            rule.tag_matchers.get("custom-tag").unwrap().pattern(),
            "tag-value"
        );
        assert_eq!(rule.provenance, "customer");
    }

    #[test]
    fn test_sampling_rule_with_no_rule() {
        // Create a rule without specifying any criteria
        let rule = SamplingRule::new(
            0.5, None, // No service
            None, // No name
            None, // No resource
            None, // No tags
            None, // Default provenance
        );

        // Verify fields are set to None or empty
        assert_eq!(rule.sample_rate, 0.5);
        assert!(rule.service_matcher.is_none());
        assert!(rule.name_matcher.is_none());
        assert!(rule.resource_matcher.is_none());
        assert!(rule.tag_matchers.is_empty());
        assert_eq!(rule.provenance, "default");

        // Verify no matchers were created
        assert!(rule.service_matcher.is_none());
        assert!(rule.name_matcher.is_none());
        assert!(rule.resource_matcher.is_none());
        assert!(rule.tag_matchers.is_empty());

        // Test that a rule with NO_RULE constants behaves the same as None
        let rule_with_empty_strings = SamplingRule::new(
            0.5,
            Some(pattern::NO_RULE.to_string()), // Empty service string
            Some(pattern::NO_RULE.to_string()), // Empty name string
            Some(pattern::NO_RULE.to_string()), // Empty resource string
            Some(HashMap::from([(
                pattern::NO_RULE.to_string(),
                pattern::NO_RULE.to_string(),
            )])), // Empty tag
            None,
        );

        // Verify that matchers aren't created for NO_RULE values
        assert!(rule_with_empty_strings.service_matcher.is_none());
        assert!(rule_with_empty_strings.name_matcher.is_none());
        assert!(rule_with_empty_strings.resource_matcher.is_none());
        assert!(rule_with_empty_strings.tag_matchers.is_empty());

        // Create a span with some attributes
        let attributes = create_attributes("some-resource", "some-env");

        // Empty resource for testing (unwrapped for the test)
        let empty_resource = create_empty_resource_for_matching();

        // Both rules should match any span since they have no criteria
        assert!(rule.matches(attributes.as_slice(), &SpanKind::Client, &empty_resource));
        assert!(rule_with_empty_strings.matches(
            attributes.as_slice(),
            &SpanKind::Client,
            &empty_resource
        ));
    }

    #[test]
    fn test_sampling_rule_matches() {
        // Create a rule with specific service and name patterns
        let _rule = SamplingRule::new(
            0.5,
            Some("web-*".to_string()),
            Some("http.*".to_string()),
            None,
            Some(HashMap::from([(
                "custom_key".to_string(),
                "custom_value".to_string(),
            )])),
            None,
        );
    }

    #[test]
    fn test_sample_method() {
        // Create two rules with different rates
        let rule_always = SamplingRule::new(1.0, None, None, None, None, None);
        let rule_never = SamplingRule::new(0.0, None, None, None, None, None);

        let trace_id = create_trace_id();

        // Rule with rate 1.0 should always sample
        assert!(rule_always.sample(trace_id));

        // Rule with rate 0.0 should never sample
        assert!(!rule_never.sample(trace_id));
    }

    #[test]
    fn test_datadog_sampler_creation() {
        // Create a sampler with default config
        let sampler = DatadogSampler::new(vec![], 100, create_empty_resource());
        assert!(sampler.rules.is_empty());
        assert!(sampler.service_samplers.is_empty());

        // Create a sampler with rules
        let rule = SamplingRule::new(0.5, None, None, None, None, None);
        let sampler_with_rules = DatadogSampler::new(vec![rule], 200, create_empty_resource());
        assert_eq!(sampler_with_rules.rules.len(), 1);
        assert_eq!(sampler_with_rules.rules[0].sample_rate, 0.5);
    }

    #[test]
    fn test_service_key_generation() {
        // Use create_resource to initialize the sampler with a service name in its resource
        let test_service_name = "test-service".to_string();
        let sampler_resource = create_resource(test_service_name.clone());
        let sampler = DatadogSampler::new(vec![], 100, sampler_resource);

        // Test with service and env
        // The 'service' in create_attributes is not used for the service part of the key,
        // but ENV_TAG is still correctly picked up from attributes.
        let attrs = create_attributes("resource", "production");
        assert_eq!(
            sampler.service_key(attrs.as_slice()),
            // Expect the service name from the sampler's resource
            format!("service:{},env:production", test_service_name)
        );

        // Test with missing env
        // The 'service' in these attributes is also not used for the service part of the key.
        let attrs_no_env = vec![KeyValue::new(RESOURCE_TAG, "resource")];
        assert_eq!(
            sampler.service_key(attrs_no_env.as_slice()),
            // Expect the service name from the sampler's resource and an empty env
            format!("service:{},env:", test_service_name)
        );
    }

    #[test]
    fn test_update_service_rates() {
        let mut sampler = DatadogSampler::new(vec![], 100, create_empty_resource());

        // Update with service rates
        let mut rates = HashMap::new();
        rates.insert("service:web,env:prod".to_string(), 0.5);
        rates.insert("service:api,env:prod".to_string(), 0.75);

        sampler.update_service_rates(rates);

        // Check number of samplers
        assert_eq!(sampler.service_samplers.len(), 2);

        // Verify keys exist
        assert!(sampler
            .service_samplers
            .contains_key("service:web,env:prod"));
        assert!(sampler
            .service_samplers
            .contains_key("service:api,env:prod"));

        // Verify the sampling rates are correctly set
        if let Some(web_sampler) = sampler.service_samplers.get("service:web,env:prod") {
            assert_eq!(web_sampler.sample_rate(), 0.5);
        } else {
            panic!("Web service sampler not found");
        }

        if let Some(api_sampler) = sampler.service_samplers.get("service:api,env:prod") {
            assert_eq!(api_sampler.sample_rate(), 0.75);
        } else {
            panic!("API service sampler not found");
        }
    }

    #[test]
    fn test_find_matching_rule() {
        // Create rules with different priorities and service matchers
        let rule1 = SamplingRule::new(
            0.1,
            Some("service1".to_string()),
            None,
            None,
            None,
            Some("customer".to_string()), // Highest priority
        );

        let rule2 = SamplingRule::new(
            0.2,
            Some("service2".to_string()),
            None,
            None,
            None,
            Some("dynamic".to_string()), // Middle priority
        );

        let rule3 = SamplingRule::new(
            0.3,
            Some("service*".to_string()), // Wildcard service
            None,
            None,
            None,
            Some("default".to_string()), // Lowest priority
        );

        // Sampler is mutable to allow resource updates
        let mut sampler = DatadogSampler::new(
            vec![rule1.clone(), rule2.clone(), rule3.clone()],
            100,
            create_empty_resource(), // Initial resource, will be updated before each check
        );

        // Test with a specific service that should match the first rule (rule1)
        sampler.resource = create_resource("service1".to_string());
        let attrs1 = create_attributes("resource_val_for_attr1", "prod");
        let matching_rule_for_attrs1 =
            sampler.find_matching_rule(attrs1.as_slice(), &SpanKind::Client);
        assert!(
            matching_rule_for_attrs1.is_some(),
            "Expected rule1 to match for service1"
        );
        assert_eq!(
            matching_rule_for_attrs1.unwrap().sample_rate,
            0.1,
            "Expected rule1 sample rate"
        );
        assert_eq!(
            matching_rule_for_attrs1.unwrap().provenance,
            "customer",
            "Expected rule1 provenance"
        );

        // Test with a specific service that should match the second rule (rule2)
        sampler.resource = create_resource("service2".to_string());
        let attrs2 = create_attributes("resource_val_for_attr2", "prod");
        let matching_rule_for_attrs2 =
            sampler.find_matching_rule(attrs2.as_slice(), &SpanKind::Client);
        assert!(
            matching_rule_for_attrs2.is_some(),
            "Expected rule2 to match for service2"
        );
        assert_eq!(
            matching_rule_for_attrs2.unwrap().sample_rate,
            0.2,
            "Expected rule2 sample rate"
        );
        assert_eq!(
            matching_rule_for_attrs2.unwrap().provenance,
            "dynamic",
            "Expected rule2 provenance"
        );

        // Test with a service that matches the wildcard rule (rule3)
        sampler.resource = create_resource("service3".to_string());
        let attrs3 = create_attributes("resource_val_for_attr3", "prod");
        let matching_rule_for_attrs3 =
            sampler.find_matching_rule(attrs3.as_slice(), &SpanKind::Client);
        assert!(
            matching_rule_for_attrs3.is_some(),
            "Expected rule3 to match for service3"
        );
        assert_eq!(
            matching_rule_for_attrs3.unwrap().sample_rate,
            0.3,
            "Expected rule3 sample rate"
        );
        assert_eq!(
            matching_rule_for_attrs3.unwrap().provenance,
            "default",
            "Expected rule3 provenance"
        );

        // Test with a service that doesn't match any rule's service pattern
        sampler.resource = create_resource("other_sampler_service".to_string());
        let attrs4 = create_attributes("resource_val_for_attr4", "prod");
        let matching_rule_for_attrs4 =
            sampler.find_matching_rule(attrs4.as_slice(), &SpanKind::Client);
        assert!(
            matching_rule_for_attrs4.is_none(),
            "Expected no rule to match for service 'other_sampler_service'"
        );
    }

    #[test]
    fn test_get_sampling_mechanism() {
        let sampler = DatadogSampler::new(vec![], 100, create_empty_resource());

        // Create rules with different provenances
        let rule_customer =
            SamplingRule::new(0.1, None, None, None, None, Some("customer".to_string()));
        let rule_dynamic =
            SamplingRule::new(0.2, None, None, None, None, Some("dynamic".to_string()));
        let rule_default =
            SamplingRule::new(0.3, None, None, None, None, Some("default".to_string()));

        // Test with customer rule
        let mechanism1 = sampler.get_sampling_mechanism(Some(&rule_customer), false);
        assert_eq!(mechanism1, mechanism::REMOTE_USER_TRACE_SAMPLING_RULE);

        // Test with dynamic rule
        let mechanism2 = sampler.get_sampling_mechanism(Some(&rule_dynamic), false);
        assert_eq!(mechanism2, mechanism::REMOTE_DYNAMIC_TRACE_SAMPLING_RULE);

        // Test with default rule
        let mechanism3 = sampler.get_sampling_mechanism(Some(&rule_default), false);
        assert_eq!(mechanism3, mechanism::LOCAL_USER_TRACE_SAMPLING_RULE);

        // Test with agent sampler
        let mechanism4 = sampler.get_sampling_mechanism(None, true);
        assert_eq!(mechanism4, mechanism::AGENT_RATE_BY_SERVICE);

        // Test fallback case
        let mechanism5 = sampler.get_sampling_mechanism(None, false);
        assert_eq!(mechanism5, mechanism::DEFAULT);
    }

    #[test]
    fn test_add_dd_sampling_tags() {
        // Test with RecordAndSample decision and LocalUserTraceSamplingRule mechanism
        let sample_rate = 0.5;
        let is_sampled = true;
        let mechanism = mechanism::LOCAL_USER_TRACE_SAMPLING_RULE;
        let sampling_result = DdSamplingResult {
            is_keep: true,
            trace_root_info: Some(TraceRootSamplingInfo {
                decision: DdSamplingDecision {
                    priority: mechanism.to_priority(is_sampled),
                    mechanism,
                },
                rate: 0.5,
                rl_effective_rate: None,
            }),
        };

        let attrs = sampling_result.to_dd_sampling_tags();

        // Verify the number of attributes
        assert_eq!(attrs.len(), 3);

        // Check individual attributes
        let mut found_decision_maker = false;
        let mut found_priority = false;
        let mut found_rule_rate = false;

        for attr in &attrs {
            match attr.key.as_str() {
                SAMPLING_DECISION_MAKER_TAG_KEY => {
                    let value_str = match &attr.value {
                        opentelemetry::Value::String(s) => s.to_string(),
                        _ => panic!("Expected string value for decision maker tag"),
                    };
                    assert_eq!(value_str, mechanism.to_cow());
                    found_decision_maker = true;
                }
                SAMPLING_PRIORITY_TAG_KEY => {
                    // For LocalUserTraceSamplingRule with KEEP, it should be USER_KEEP
                    let expected_priority = mechanism.to_priority(true).into_i8() as i64;

                    let value_int = match attr.value {
                        opentelemetry::Value::I64(i) => i,
                        _ => panic!("Expected integer value for priority tag"),
                    };
                    assert_eq!(value_int, expected_priority);
                    found_priority = true;
                }
                SAMPLING_RULE_RATE_TAG_KEY => {
                    let value_float = match attr.value {
                        opentelemetry::Value::F64(f) => f,
                        _ => panic!("Expected float value for rule rate tag"),
                    };
                    assert_eq!(value_float, sample_rate);
                    found_rule_rate = true;
                }
                _ => {}
            }
        }

        assert!(found_decision_maker, "Missing decision maker tag");
        assert!(found_priority, "Missing priority tag");
        assert!(found_rule_rate, "Missing rule rate tag");

        // Test with rate limiting
        let rate_limit = 100;
        let is_sampled = false;
        let mechanism = mechanism::LOCAL_USER_TRACE_SAMPLING_RULE;
        let sampling_result = DdSamplingResult {
            is_keep: false,
            trace_root_info: Some(TraceRootSamplingInfo {
                decision: DdSamplingDecision {
                    priority: mechanism.to_priority(is_sampled),
                    mechanism,
                },
                rate: 0.5,
                rl_effective_rate: Some(rate_limit),
            }),
        };
        let attrs_with_limit = sampling_result.to_dd_sampling_tags();

        // With rate limiting, there should be one more attribute
        assert_eq!(attrs_with_limit.len(), 4);

        // Check for rate limit attribute
        let mut found_limit = false;
        for attr in &attrs_with_limit {
            if attr.key.as_str() == RL_EFFECTIVE_RATE {
                let value_int = match attr.value {
                    opentelemetry::Value::I64(i) => i,
                    _ => panic!("Expected integer value for rate limit tag"),
                };
                assert_eq!(value_int, rate_limit as i64);
                found_limit = true;
                break;
            }
        }

        assert!(found_limit, "Missing rate limit tag");

        // Test with AgentRateByService mechanism to check for SAMPLING_AGENT_RATE_TAG_KEY

        let agent_rate = 0.75;
        let is_sampled = false;
        let mechanism = mechanism::AGENT_RATE_BY_SERVICE;
        let sampling_result = DdSamplingResult {
            is_keep: false,
            trace_root_info: Some(TraceRootSamplingInfo {
                decision: DdSamplingDecision {
                    priority: mechanism.to_priority(is_sampled),
                    mechanism,
                },
                rate: agent_rate,
                rl_effective_rate: None,
            }),
        };

        let agent_attrs = sampling_result.to_dd_sampling_tags();

        // Verify the number of attributes (should be 3)
        assert_eq!(agent_attrs.len(), 3);

        // Check for agent rate tag specifically
        let mut found_agent_rate = false;
        for attr in &agent_attrs {
            if attr.key.as_str() == SAMPLING_AGENT_RATE_TAG_KEY {
                let value_float = match attr.value {
                    opentelemetry::Value::F64(f) => f,
                    _ => panic!("Expected float value for agent rate tag"),
                };
                assert_eq!(value_float, agent_rate);
                found_agent_rate = true;
                break;
            }
        }

        assert!(found_agent_rate, "Missing agent rate tag");

        // Also check that the SAMPLING_RULE_RATE_TAG_KEY is NOT present for agent mechanism
        for attr in &agent_attrs {
            assert_ne!(
                attr.key.as_str(),
                SAMPLING_RULE_RATE_TAG_KEY,
                "Rule rate tag should not be present for agent mechanism"
            );
        }
    }

    #[test]
    fn test_should_sample_parent_context() {
        let sampler = DatadogSampler::new(vec![], 100, create_empty_resource());

        // Create empty slices for attributes and links
        let empty_attrs: &[KeyValue] = &[];

        // Test with sampled parent context
        // let parent_sampled = create_parent_context(true);
        let result_sampled = sampler.sample(
            Some(true),
            create_trace_id(),
            "span",
            &SpanKind::Client,
            empty_attrs,
        );

        // Should inherit the sampling decision from parent
        assert_eq!(
            result_sampled.to_otel_decision(),
            SamplingDecision::RecordAndSample
        );
        assert!(result_sampled.to_dd_sampling_tags().is_empty());

        // Test with non-sampled parent context
        let result_not_sampled = sampler.sample(
            Some(false),
            create_trace_id(),
            "span",
            &SpanKind::Client,
            empty_attrs,
        );

        // Should inherit the sampling decision from parent
        assert_eq!(
            result_not_sampled.to_otel_decision(),
            SamplingDecision::RecordOnly
        );
        assert!(result_not_sampled.to_dd_sampling_tags().is_empty());
    }

    #[test]
    fn test_should_sample_with_rule() {
        // Create a rule that always samples
        let rule = SamplingRule::new(
            1.0,
            Some("test-service".to_string()),
            None,
            None,
            None,
            None,
        );

        let sampler = DatadogSampler::new(vec![rule], 100, create_empty_resource());

        // Test with matching attributes
        let attrs = create_attributes("resource", "prod");
        let result = sampler.sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs.as_slice(),
        );

        // Should sample and add attributes
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);
        assert!(!result.to_dd_sampling_tags().is_empty());

        // Test with non-matching attributes
        let attrs_no_match = create_attributes("other-resource", "prod");
        let result_no_match = sampler.sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs_no_match.as_slice(),
        );

        // Should still sample (default behavior when no rules match) and add attributes
        assert_eq!(
            result_no_match.to_otel_decision(),
            SamplingDecision::RecordAndSample
        );
        assert!(!result_no_match.to_dd_sampling_tags().is_empty());
    }

    #[test]
    fn test_should_sample_with_service_rates() {
        // Initialize sampler with a default service, e.g., "test-service"
        // The sampler's own service name will be used for the 'service:' part of the service_key
        let mut sampler =
            DatadogSampler::new(vec![], 100, create_resource("test-service".to_string()));

        // Add service rates for different service+env combinations
        let mut rates = HashMap::new();
        rates.insert("service:test-service,env:prod".to_string(), 1.0); // Always sample for test-service in prod
        rates.insert("service:other-service,env:prod".to_string(), 0.0); // Never sample for other-service in prod

        sampler.update_service_rates(rates);

        // Test with attributes that should lead to "service:test-service,env:prod" key
        // Sampler's resource is already for "test-service"
        let attrs_sample = create_attributes("any_resource_name_matching_env", "prod");
        let result_sample = sampler.sample(
            None,
            create_trace_id(),
            "span_for_test_service",
            &SpanKind::Client,
            attrs_sample.as_slice(),
        );
        // Expect RecordAndSample because service_key will be "service:test-service,env:prod" ->
        // rate 1.0
        assert_eq!(
            result_sample.to_otel_decision(),
            SamplingDecision::RecordAndSample,
            "Span for test-service/prod should be sampled"
        );

        // Test with attributes that should lead to "service:other-service,env:prod" key
        // Update sampler's resource to be "other-service"
        sampler.resource = create_resource("other-service".to_string());
        let attrs_no_sample = create_attributes("any_resource_name_matching_env", "prod");
        let result_no_sample = sampler.sample(
            None,
            create_trace_id(),
            "span_for_other_service",
            &SpanKind::Client,
            attrs_no_sample.as_slice(),
        );
        // Expect Drop because service_key will be "service:other-service,env:prod" -> rate 0.0
        assert_eq!(
            result_no_sample.to_otel_decision(),
            SamplingDecision::RecordOnly,
            "Span for other-service/prod should be dropped"
        );
    }

    #[test]
    fn test_sampling_rule_matches_float_attributes() {
        use opentelemetry::Value;

        // Helper to create attributes with a float value
        fn create_attributes_with_float(tag_key: &'static str, float_value: f64) -> Vec<KeyValue> {
            vec![
                KeyValue::new(RESOURCE_TAG, "resource"),
                KeyValue::new(ENV_TAG, "prod"),
                KeyValue::new(tag_key, Value::F64(float_value)),
            ]
        }

        // Test case 1: Rule with exact value matching integer float
        let rule_integer = SamplingRule::new(
            0.5,
            None,
            None,
            None,
            Some(HashMap::from([("float_tag".to_string(), "42".to_string())])),
            None,
        );

        // Should match integer float
        let integer_float_attrs = create_attributes_with_float("float_tag", 42.0);
        assert!(rule_integer.matches(
            integer_float_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Test case 2: Rule with wildcard pattern and non-integer float
        let rule_wildcard = SamplingRule::new(
            0.5,
            None,
            None,
            None,
            Some(HashMap::from([("float_tag".to_string(), "*".to_string())])),
            None,
        );

        // Should match non-integer float with wildcard pattern
        let decimal_float_attrs = create_attributes_with_float("float_tag", 42.5);
        assert!(rule_wildcard.matches(
            decimal_float_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Test case 3: Rule with specific pattern and non-integer float
        // With our simplified logic, non-integer floats will never match non-wildcard patterns
        let rule_specific = SamplingRule::new(
            0.5,
            None,
            None,
            None,
            Some(HashMap::from([(
                "float_tag".to_string(),
                "42.5".to_string(),
            )])),
            None,
        );

        // Should NOT match the exact decimal value because non-integer floats only match wildcards
        let decimal_float_attrs = create_attributes_with_float("float_tag", 42.5);
        assert!(!rule_specific.matches(
            decimal_float_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));
        // Test case 4: Pattern with partial wildcard '*' for suffix
        let rule_prefix = SamplingRule::new(
            0.5,
            None,
            None,
            None,
            Some(HashMap::from([(
                "float_tag".to_string(),
                "42.*".to_string(),
            )])),
            None,
        );

        // Should NOT match decimal values as we don't do partial pattern matching for non-integer
        // floats
        assert!(!rule_prefix.matches(
            decimal_float_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));
    }

    #[test]
    fn test_otel_to_datadog_attribute_mapping() {
        // Test with a rule that matches against a Datadog attribute name
        let rule = SamplingRule::new(
            1.0,
            None,
            None,
            None,
            Some(HashMap::from([(
                "http.status_code".to_string(),
                "5*".to_string(),
            )])),
            None,
        );

        // Create attributes with OpenTelemetry naming convention
        let otel_attrs = vec![
            // OpenTelemetry uses http.response.status_code, but Datadog uses http.status_code
            KeyValue::new("http.response.status_code", 500),
        ];

        // The rule should match because http.response.status_code maps to http.status_code
        assert!(rule.matches(
            otel_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Create attributes with Datadog naming convention (direct match)
        let dd_attrs = vec![KeyValue::new("http.status_code", 500)];

        // Direct match should also work
        assert!(rule.matches(
            dd_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Attributes that don't match the value pattern shouldn't match
        let non_matching_attrs = vec![KeyValue::new("http.response.status_code", 200)];
        assert!(!rule.matches(
            non_matching_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Attributes that have no mapping to the rule tag shouldn't match
        let unrelated_attrs = vec![KeyValue::new("unrelated.attribute", "value")];
        assert!(!rule.matches(
            unrelated_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));
    }

    #[test]
    fn test_multiple_otel_attribute_mappings() {
        // Test with a rule that has multiple tag criteria
        let mut tags = HashMap::new();
        tags.insert("http.status_code".to_string(), "5*".to_string());
        tags.insert("http.method".to_string(), "POST".to_string());
        tags.insert("http.url".to_string(), "*api*".to_string());

        let rule = SamplingRule::new(1.0, None, None, None, Some(tags), None);

        // Create attributes with mixed OpenTelemetry and Datadog naming
        let mixed_attrs = vec![
            // OTel attribute that maps to http.status_code
            KeyValue::new("http.response.status_code", 503),
            // OTel attribute that maps to http.method
            KeyValue::new("http.request.method", "POST"),
            // OTel attribute that maps to http.url
            KeyValue::new("url.full", "https://example.com/api/v1/resource"),
        ];

        // The rule should match because all three criteria are satisfied through mapping
        assert!(rule.matches(
            mixed_attrs.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // If any criteria is not met, the rule shouldn't match
        let missing_method = vec![
            KeyValue::new("http.response.status_code", 503),
            // Missing http.method/http.request.method
            KeyValue::new("url.full", "https://example.com/api/v1/resource"),
        ];

        assert!(!rule.matches(
            missing_method.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));

        // Wrong value should also not match
        let wrong_method = vec![
            KeyValue::new("http.response.status_code", 503),
            KeyValue::new("http.request.method", "GET"), // Not POST
            KeyValue::new("url.full", "https://example.com/api/v1/resource"),
        ];

        assert!(!rule.matches(
            wrong_method.as_slice(),
            &SpanKind::Client,
            &create_empty_resource()
        ));
    }

    #[test]
    fn test_direct_and_mapped_mixed_attributes() {
        // Constants for key names to improve readability and ensure consistency
        let dd_status_key_str = crate::sem_convs::ATTRIBUTE_HTTP_STATUS_CODE;
        let otel_response_status_key_str = crate::sem_convs::ATTRIBUTE_HTTP_RESPONSE_STATUS_CODE;
        let custom_tag_key = "custom.tag";
        let custom_tag_value = "value";

        let empty_resource = create_empty_resource_for_matching();
        let span_kind_client = SpanKind::Client;

        // Test with both direct matches and mapped attributes
        let mut tags_rule1 = HashMap::new();
        tags_rule1.insert(dd_status_key_str.to_string(), "5*".to_string());
        tags_rule1.insert(custom_tag_key.to_string(), custom_tag_value.to_string());

        let rule1 = SamplingRule::new(1.0, None, None, None, Some(tags_rule1), None);

        // Case 1: OTel attribute that maps to http.status_code (503 matches "5*") + Direct
        // custom.tag match
        let mixed_attrs_match = vec![
            KeyValue::new(otel_response_status_key_str, 503),
            KeyValue::new(custom_tag_key, custom_tag_value),
        ];
        assert!(rule1.matches(
            &mixed_attrs_match,
            &span_kind_client,
            &empty_resource
        ), "Rule with dd_status_key (5*) and custom.tag should match span with otel_response_status_key (503) and custom.tag");

        // Case 2: Datadog convention for status code (503 matches "5*") + Direct custom.tag match
        let dd_attrs_match = vec![
            KeyValue::new(dd_status_key_str, 503),
            KeyValue::new(custom_tag_key, custom_tag_value),
        ];
        assert!(rule1.matches(
            &dd_attrs_match,
            &span_kind_client,
            &empty_resource
        ), "Rule with dd_status_key (5*) and custom.tag should match span with dd_status_key (503) and custom.tag");

        // Case 3: Missing the custom tag should fail (status code would match)
        let missing_custom_tag_attrs = vec![KeyValue::new(otel_response_status_key_str, 503)];
        assert!(
            !rule1.matches(
                &missing_custom_tag_attrs,
                &span_kind_client,
                &empty_resource
            ),
            "Rule with dd_status_key (5*) and custom.tag should NOT match span missing custom.tag"
        );

        // Case 4: OTel status code 200 (does NOT match "5*") + custom.tag present
        let non_matching_otel_status_attrs = vec![
            KeyValue::new(otel_response_status_key_str, 200),
            KeyValue::new(custom_tag_key, custom_tag_value),
        ];
        assert!(!rule1.matches(
            &non_matching_otel_status_attrs,
            &span_kind_client,
            &empty_resource
        ), "Rule with dd_status_key (5*) and custom.tag should NOT match span with non-matching otel_response_status_key (200)");

        // Case 5: No recognizable status code + custom.tag present
        let no_status_code_attrs = vec![
            KeyValue::new("another.tag", "irrelevant"),
            KeyValue::new(custom_tag_key, custom_tag_value),
        ];
        assert!(!rule1.matches(
            &no_status_code_attrs,
            &span_kind_client,
            &empty_resource
        ), "Rule with dd_status_key (5*) and custom.tag should NOT match span with no status code attribute");

        // Case 6: Rule uses OTel key http.response.status_code directly, span has matching OTel
        // key.
        let mut tags_rule2 = HashMap::new();
        tags_rule2.insert(otel_response_status_key_str.to_string(), "200".to_string());
        tags_rule2.insert(custom_tag_key.to_string(), custom_tag_value.to_string());
        let rule2 = SamplingRule::new(1.0, None, None, None, Some(tags_rule2), None);

        let otel_key_rule_match_attrs = vec![
            KeyValue::new(otel_response_status_key_str, 200),
            KeyValue::new(custom_tag_key, custom_tag_value),
        ];
        assert!(rule2.matches(
            &otel_key_rule_match_attrs,
            &span_kind_client,
            &empty_resource
        ), "Rule with otel_response_status_key (200) and custom.tag should match span with otel_response_status_key (200) and custom.tag");
    }

    #[test]
    fn test_operation_name_integration() {
        // Create rules that match different operation name patterns
        let http_rule = SamplingRule::new(
            1.0,                                // 100% sample rate
            None,                               // no service matcher
            Some("http.*.request".to_string()), // matches both client and server HTTP requests
            None,                               // no resource matcher
            None,                               // no tag matchers
            Some("default".to_string()),        // rule name - default provenance
        );

        let db_rule = SamplingRule::new(
            1.0,                                  // 100% sample rate
            None,                                 // no service matcher
            Some("postgresql.query".to_string()), // matches database queries
            None,                                 // no resource matcher
            None,                                 // no tag matchers
            Some("default".to_string()),          // rule name - default provenance
        );

        let messaging_rule = SamplingRule::new(
            1.0,                               // 100% sample rate
            None,                              // no service matcher
            Some("kafka.process".to_string()), // matches Kafka messaging operations
            None,                              // no resource matcher
            None,                              // no tag matchers
            Some("default".to_string()),       // rule name - default provenance
        );

        // Create a sampler with these rules
        let sampler = DatadogSampler::new(
            vec![http_rule, db_rule, messaging_rule],
            100,
            create_empty_resource(),
        );

        // Create a trace ID for testing
        let trace_id = create_trace_id();

        // Test cases for different span kinds and attributes

        // 1. HTTP client request
        let http_client_attrs = vec![KeyValue::new(
            Key::from_static_str(HTTP_METHOD.key()),
            Value::String("GET".into()),
        )];

        // Print the operation name that will be generated
        let http_client_op_name = get_otel_operation_name_v2(&http_client_attrs, &SpanKind::Client);
        assert_eq!(
            http_client_op_name, "http.client.request",
            "HTTP client operation name should be correct"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Client,
            &http_client_attrs,
        );

        // Should be sampled due to matching the http_rule
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);

        // 2. HTTP server request
        let http_server_attrs = vec![KeyValue::new(
            Key::from_static_str(HTTP_METHOD.key()),
            Value::String("POST".into()),
        )];

        // Print the operation name that will be generated
        let http_server_op_name = get_otel_operation_name_v2(&http_server_attrs, &SpanKind::Server);
        assert_eq!(
            http_server_op_name, "http.server.request",
            "HTTP server operation name should be correct"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Server,
            &http_server_attrs,
        );

        // Should be sampled due to matching the http_rule
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);

        // 3. Database query
        let db_attrs = vec![KeyValue::new(
            Key::from_static_str(DB_SYSTEM.key()),
            Value::String("postgresql".into()),
        )];

        // Print the operation name that will be generated
        let db_op_name = get_otel_operation_name_v2(&db_attrs, &SpanKind::Client);
        assert_eq!(
            db_op_name, "postgresql.query",
            "Database operation name should be correct"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Client, // DB queries use client span kind
            &db_attrs,
        );

        // Should be sampled due to matching the db_rule
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);

        // 4. Messaging operation
        let messaging_attrs = vec![
            KeyValue::new(
                Key::from_static_str(MESSAGING_SYSTEM.key()),
                Value::String("kafka".into()),
            ),
            KeyValue::new(
                Key::from_static_str(MESSAGING_OPERATION.key()),
                Value::String("process".into()),
            ),
        ];

        // Print the operation name that will be generated
        let messaging_op_name = get_otel_operation_name_v2(&messaging_attrs, &SpanKind::Consumer);
        assert_eq!(
            messaging_op_name, "kafka.process",
            "Messaging operation name should be correct"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Consumer, // Messaging uses consumer span kind
            &messaging_attrs,
        );

        // Should be sampled due to matching the messaging_rule
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);

        // 5. Generic internal span (should not match any rules)
        let internal_attrs = vec![KeyValue::new("custom.tag", "value")];

        // Print the operation name that will be generated
        let internal_op_name = get_otel_operation_name_v2(&internal_attrs, &SpanKind::Internal);
        assert_eq!(
            internal_op_name, "Internal",
            "Internal operation name should be the span kind"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Internal,
            &internal_attrs,
        );

        // Should still be sampled (default behavior when no rules match)
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);

        // 6. Server with protocol but no HTTP method
        let server_protocol_attrs = vec![KeyValue::new(
            Key::from_static_str(NETWORK_PROTOCOL_NAME.key()),
            Value::String("http".into()),
        )];

        // Print the operation name that will be generated
        let server_protocol_op_name =
            get_otel_operation_name_v2(&server_protocol_attrs, &SpanKind::Server);
        assert_eq!(
            server_protocol_op_name, "http.server.request",
            "Server with protocol operation name should use protocol"
        );

        let result = sampler.sample(
            None,
            trace_id,
            "test-span",
            &SpanKind::Server,
            &server_protocol_attrs,
        );

        // Should not match our http rule since operation name would be "http.server.request"
        // But should still be sampled (default behavior)
        assert_eq!(result.to_otel_decision(), SamplingDecision::RecordAndSample);
    }
}
