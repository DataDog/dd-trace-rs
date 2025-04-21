// Copyright 2023-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::TraceId;
use opentelemetry::trace::{SamplingDecision, SamplingResult, TraceContextExt};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::trace::ShouldSample;
use serde_json;
use std::collections::HashMap;

use crate::constants::{
    SamplingMechanism, KEEP_PRIORITY_INDEX, REJECT_PRIORITY_INDEX, SAMPLING_AGENT_RATE_TAG_KEY,
    SAMPLING_DECISION_MAKER_TAG_KEY, SAMPLING_LIMIT_DECISION, SAMPLING_MECHANISM_TO_PRIORITIES,
    SAMPLING_PRIORITY_TAG_KEY, SAMPLING_RULE_RATE_TAG_KEY,
};

// Import the attr constants
use crate::constants::attr::{ENV_TAG, RESOURCE_TAG, SERVICE_TAG};

use crate::glob_matcher::GlobMatcher;
use crate::rate_limiter::RateLimiter;
use crate::rate_sampler::RateSampler;
use crate::utils;

/// Constant to represent "no rule" for a field
pub const NO_RULE: &str = "";

/// Represents a sampling rule with criteria for matching spans
#[derive(Clone, Debug)]
pub struct SamplingRule {
    /// The sample rate to apply when this rule matches (0.0-1.0)
    pub sample_rate: f64,

    /// Optional service name to match (checked in span attributes for "SERVICE_TAG")
    pub service: Option<String>,

    /// Optional span name to match
    pub name: Option<String>,

    /// Optional resource name to match (checked in span attributes for "RESOURCE_TAG")
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
                utils::extract_string_value(&kv.value).map(|val| (kv.key.as_str(), val))
            })
            .collect();

        // Check service if specified using glob matcher
        if let Some(ref matcher) = self.service_matcher {
            match attr_map.get(SERVICE_TAG) {
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
            match attr_map.get(RESOURCE_TAG) {
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
        self.rate_sampler
            .should_sample(
                None,
                trace_id,
                "", // name not needed for rate sampler
                &opentelemetry::trace::SpanKind::Client,
                &[],
                &[],
            )
            .decision
            == SamplingDecision::RecordAndSample
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
}

impl DatadogSampler {
    /// Creates a new DatadogSampler with the given rules
    pub fn new(rules: Option<Vec<SamplingRule>>, rate_limit: Option<i32>) -> Self {
        // Sort rules by provenance if provided
        let sorted_rules = if let Some(mut r) = rules {
            r.sort_by_key(|rule| RuleProvenance::from(rule.provenance.as_str()));
            r
        } else {
            Vec::new()
        };

        // Create rate limiter with default value of 100 if not provided
        let limiter = RateLimiter::new(rate_limit.unwrap_or(100), None);

        DatadogSampler {
            rules: sorted_rules,
            service_samplers: HashMap::new(),
            rate_limiter: limiter,
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
                if let Some(val) = utils::extract_string_value(&attr.value) {
                    service = val;
                }
            } else if attr.key.as_str() == ENV_TAG {
                if let Some(val) = utils::extract_string_value(&attr.value) {
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
        self.rules
            .iter()
            .find(|rule| rule.matches(name, attributes))
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
    /// * `rate_limit` - The rate limit if rate limiting was applied
    ///
    /// # Returns
    /// A vector of attributes to add to the sampling result
    fn add_dd_sampling_tags(
        &self,
        decision: &SamplingDecision,
        mechanism: SamplingMechanism,
        sample_rate: f64,
        rate_limit: Option<i32>,
    ) -> Vec<KeyValue> {
        let mut result = Vec::new();

        // Add rate limiting tag if applicable
        if let Some(limit) = rate_limit {
            result.push(KeyValue::new(SAMPLING_LIMIT_DECISION, limit as i64));
        }

        // Add the sampling decision trace tag with the mechanism
        result.push(KeyValue::new(
            SAMPLING_DECISION_MAKER_TAG_KEY,
            format!("-{}", mechanism.value()),
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
            priority.value() as i64,
        ));

        // Add the sample rate tag with the correct key based on the mechanism
        match mechanism {
            SamplingMechanism::AgentRateByService => {
                result.push(KeyValue::new(SAMPLING_AGENT_RATE_TAG_KEY, sample_rate));
            }
            SamplingMechanism::RemoteUserTraceSamplingRule
            | SamplingMechanism::RemoteDynamicTraceSamplingRule
            | SamplingMechanism::LocalUserTraceSamplingRule => {
                result.push(KeyValue::new(SAMPLING_RULE_RATE_TAG_KEY, sample_rate));
            }
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

        // Store rate limit information if applicable
        let mut rate_limit: Option<i32> = None;

        // Apply sampling logic
        if let Some(rule) = matching_rule {
            // Get the sample rate from the rule
            sample_rate = rule.sample_rate;

            // First check if the span should be sampled according to the rule
            if !rule.sample(trace_id) {
                decision = SamplingDecision::Drop;
            }
            // If the span should be sampled, then apply rate limiting
            else if !self.rate_limiter.is_allowed() {
                decision = SamplingDecision::Drop;
                rate_limit = Some(self.rate_limiter.effective_rate() as i32);
            }
        } else {
            // Try service-based sampling from Agent
            let service_key = self.service_key(attributes);
            if let Some(sampler) = self.service_samplers.get(&service_key) {
                // Use the service-based sampler
                used_agent_sampler = true;
                sample_rate = sampler.sample_rate();

                // For service-based sampling, don't apply rate limiting
                let result = sampler.should_sample(
                    None,
                    trace_id,
                    "",
                    &opentelemetry::trace::SpanKind::Client,
                    &[],
                    &[],
                );
                if result.decision == SamplingDecision::Drop {
                    decision = SamplingDecision::Drop;
                }
            } else {
                // Default sample rate, should never happen
                sample_rate = 1.0;
                // Keep the default decision (RecordAndSample)
            }
        }

        // Determine the sampling mechanism
        let mechanism = self.get_sampling_mechanism(matching_rule, used_agent_sampler);

        // Add Datadog-specific sampling tags
        let result_attributes =
            self.add_dd_sampling_tags(&decision, mechanism, sample_rate, rate_limit);

        SamplingResult {
            decision,
            attributes: result_attributes,
            trace_state: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{Span, SpanContext, SpanId};
    use opentelemetry::trace::{SpanKind, Status, TraceFlags, TraceState};
    use opentelemetry::Context as OtelContext;
    use std::borrow::Cow;

    // Helper function to create a trace ID
    fn create_trace_id() -> TraceId {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        TraceId::from_bytes(bytes)
    }

    // Helper function to create attributes for testing
    fn create_attributes(
        service: &'static str,
        resource: &'static str,
        env: &'static str,
    ) -> Vec<KeyValue> {
        vec![
            KeyValue::new(SERVICE_TAG, service),
            KeyValue::new(RESOURCE_TAG, resource),
            KeyValue::new(ENV_TAG, env),
        ]
    }

    // Helper function to create attributes with a custom tag
    fn create_attributes_with_custom_tag(
        service: &'static str,
        resource: &'static str,
        tag_key: &'static str,
        tag_value: &'static str,
    ) -> Vec<KeyValue> {
        vec![
            KeyValue::new(SERVICE_TAG, service),
            KeyValue::new(RESOURCE_TAG, resource),
            KeyValue::new(tag_key, tag_value),
        ]
    }

    // Helper function to create a parent context
    fn create_parent_context(sampled: bool) -> OtelContext {
        let span_context = SpanContext::new(
            create_trace_id(),
            SpanId::from(42u64),
            if sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::default()
            },
            false,
            TraceState::default(),
        );

        // Create an implementation of Span for testing
        #[derive(Debug)]
        struct TestSpan {
            ctx: SpanContext,
        }

        impl Span for TestSpan {
            fn span_context(&self) -> &SpanContext {
                &self.ctx
            }

            fn is_recording(&self) -> bool {
                true
            }

            fn add_event<T>(&mut self, _name: T, _attributes: Vec<KeyValue>)
            where
                T: Into<Cow<'static, str>>,
            {
                // Not implemented for test
            }

            fn add_event_with_timestamp<T>(
                &mut self,
                _name: T,
                _timestamp: std::time::SystemTime,
                _attributes: Vec<KeyValue>,
            ) where
                T: Into<Cow<'static, str>>,
            {
                // Not implemented for test
            }

            fn set_attributes(&mut self, _attributes: impl IntoIterator<Item = KeyValue>) {
                // Not implemented for test
            }

            fn set_status(&mut self, _status: Status) {
                // Not implemented for test
            }

            fn update_name<T>(&mut self, _new_name: T)
            where
                T: Into<Cow<'static, str>>,
            {
                // Not implemented for test
            }

            fn end_with_timestamp(&mut self, _timestamp: std::time::SystemTime) {
                // Not implemented for test
            }

            fn set_attribute(&mut self, _attribute: KeyValue) {
                // Not implemented for test
            }

            fn add_link(&mut self, _span_context: SpanContext, _attributes: Vec<KeyValue>) {
                // Not implemented for test
            }
        }

        let span = TestSpan { ctx: span_context };
        OtelContext::current_with_span(span)
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
        assert_eq!(rule.service, Some("test-service".to_string()));
        assert_eq!(rule.name, Some("test-name".to_string()));
        assert_eq!(rule.resource, Some("test-resource".to_string()));
        assert_eq!(rule.tags.get("custom-tag"), Some(&"tag-value".to_string()));
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
        assert_eq!(rule.service, None);
        assert_eq!(rule.name, None);
        assert_eq!(rule.resource, None);
        assert!(rule.tags.is_empty());
        assert_eq!(rule.provenance, "default");

        // Verify no matchers were created
        assert!(rule.service_matcher.is_none());
        assert!(rule.name_matcher.is_none());
        assert!(rule.resource_matcher.is_none());
        assert!(rule.tag_matchers.is_empty());

        // Test that a rule with NO_RULE constants behaves the same as None
        let rule_with_empty_strings = SamplingRule::new(
            0.5,
            Some(NO_RULE.to_string()), // Empty service string
            Some(NO_RULE.to_string()), // Empty name string
            Some(NO_RULE.to_string()), // Empty resource string
            Some(HashMap::from([(NO_RULE.to_string(), NO_RULE.to_string())])), // Empty tag
            None,
        );

        // Verify that matchers aren't created for NO_RULE values
        assert!(rule_with_empty_strings.service_matcher.is_none());
        assert!(rule_with_empty_strings.name_matcher.is_none());
        assert!(rule_with_empty_strings.resource_matcher.is_none());
        assert!(rule_with_empty_strings.tag_matchers.is_empty());

        // Create a span with some attributes
        let attributes = create_attributes("some-service", "some-resource", "some-env");

        // Both rules should match any span since they have no criteria
        assert!(rule.matches("some-span", attributes.as_slice()));
        assert!(rule_with_empty_strings.matches("some-span", attributes.as_slice()));
    }

    #[test]
    fn test_sampling_rule_matches() {
        // Create a rule with specific service and name patterns
        let rule = SamplingRule::new(
            0.5,
            Some("web-*".to_string()),
            Some("http-*".to_string()),
            None,
            Some(HashMap::from([(
                "custom_key".to_string(),
                "custom_value".to_string(),
            )])),
            None,
        );

        // Should match this span
        let matching_attributes = create_attributes_with_custom_tag(
            "web-service",
            "some-resource",
            "custom_key",
            "custom_value",
        );
        assert!(rule.matches("http-request", matching_attributes.as_slice()));

        // Should not match due to wrong service pattern
        let wrong_service = create_attributes_with_custom_tag(
            "api-service",
            "some-resource",
            "custom_key",
            "custom_value",
        );
        assert!(!rule.matches("http-request", wrong_service.as_slice()));

        // Should not match due to wrong name pattern
        assert!(!rule.matches("grpc-request", matching_attributes.as_slice()));

        // Should not match due to wrong tag value
        let wrong_tag_value = create_attributes_with_custom_tag(
            "web-service",
            "some-resource",
            "custom_key",
            "different_value",
        );
        assert!(!rule.matches("http-request", wrong_tag_value.as_slice()));

        // Should not match due to wrong tag key
        let wrong_tag_key = create_attributes_with_custom_tag(
            "web-service",
            "some-resource",
            "different_key",
            "custom_value",
        );
        assert!(!rule.matches("http-request", wrong_tag_key.as_slice()));
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
        let sampler = DatadogSampler::new(None, None);
        assert!(sampler.rules.is_empty());
        assert!(sampler.service_samplers.is_empty());

        // Create a sampler with rules
        let rule = SamplingRule::new(0.5, None, None, None, None, None);
        let sampler_with_rules = DatadogSampler::new(Some(vec![rule]), Some(200));
        assert_eq!(sampler_with_rules.rules.len(), 1);
        assert_eq!(sampler_with_rules.rules[0].sample_rate, 0.5);
    }

    #[test]
    fn test_service_key_generation() {
        let sampler = DatadogSampler::new(None, None);

        // Test with service and env
        let attrs = create_attributes("test-service", "resource", "production");
        assert_eq!(
            sampler.service_key(attrs.as_slice()),
            "service:test-service,env:production"
        );

        // Test with missing env
        let attrs_no_env = vec![
            KeyValue::new(SERVICE_TAG, "test-service"),
            KeyValue::new(RESOURCE_TAG, "resource"),
        ];
        assert_eq!(
            sampler.service_key(attrs_no_env.as_slice()),
            "service:test-service,env:"
        );
    }

    #[test]
    fn test_update_service_rates() {
        let mut sampler = DatadogSampler::new(None, None);

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
        // Create rules with different priorities
        let rule1 = SamplingRule::new(
            0.1,
            Some("service1".to_string()),
            None,
            None,
            None,
            Some("customer".to_string()),
        );

        let rule2 = SamplingRule::new(
            0.2,
            Some("service2".to_string()),
            None,
            None,
            None,
            Some("dynamic".to_string()),
        );

        let rule3 = SamplingRule::new(
            0.3,
            Some("service*".to_string()),
            None,
            None,
            None,
            Some("default".to_string()),
        );

        let sampler = DatadogSampler::new(Some(vec![rule1, rule2, rule3]), None);

        // Test with a specific service that matches the first rule
        let attrs1 = create_attributes("service1", "resource", "prod");
        let matching_rule1 = sampler.find_matching_rule("span", attrs1.as_slice());
        assert!(matching_rule1.is_some());
        assert_eq!(matching_rule1.unwrap().sample_rate, 0.1);

        // Test with a specific service that matches the second rule
        let attrs2 = create_attributes("service2", "resource", "prod");
        let matching_rule2 = sampler.find_matching_rule("span", attrs2.as_slice());
        assert!(matching_rule2.is_some());
        assert_eq!(matching_rule2.unwrap().sample_rate, 0.2);

        // Test with a service that matches the wildcard rule
        let attrs3 = create_attributes("service3", "resource", "prod");
        let matching_rule3 = sampler.find_matching_rule("span", attrs3.as_slice());
        assert!(matching_rule3.is_some());
        assert_eq!(matching_rule3.unwrap().sample_rate, 0.3);

        // Test with a service that doesn't match any rule
        let attrs4 = create_attributes("other", "resource", "prod");
        let matching_rule4 = sampler.find_matching_rule("span", attrs4.as_slice());
        assert!(matching_rule4.is_none());
    }

    #[test]
    fn test_get_sampling_mechanism() {
        let sampler = DatadogSampler::new(None, None);

        // Create rules with different provenances
        let rule_customer =
            SamplingRule::new(0.1, None, None, None, None, Some("customer".to_string()));
        let rule_dynamic =
            SamplingRule::new(0.2, None, None, None, None, Some("dynamic".to_string()));
        let rule_default =
            SamplingRule::new(0.3, None, None, None, None, Some("default".to_string()));

        // Test with customer rule
        let mechanism1 = sampler.get_sampling_mechanism(Some(&rule_customer), false);
        assert_eq!(mechanism1, SamplingMechanism::RemoteUserTraceSamplingRule);

        // Test with dynamic rule
        let mechanism2 = sampler.get_sampling_mechanism(Some(&rule_dynamic), false);
        assert_eq!(
            mechanism2,
            SamplingMechanism::RemoteDynamicTraceSamplingRule
        );

        // Test with default rule
        let mechanism3 = sampler.get_sampling_mechanism(Some(&rule_default), false);
        assert_eq!(mechanism3, SamplingMechanism::LocalUserTraceSamplingRule);

        // Test with agent sampler
        let mechanism4 = sampler.get_sampling_mechanism(None, true);
        assert_eq!(mechanism4, SamplingMechanism::AgentRateByService);

        // Test fallback case
        let mechanism5 = sampler.get_sampling_mechanism(None, false);
        assert_eq!(mechanism5, SamplingMechanism::Default);
    }

    #[test]
    fn test_add_dd_sampling_tags() {
        let sampler = DatadogSampler::new(None, None);

        // Test with RecordAndSample decision and LocalUserTraceSamplingRule mechanism
        let decision = SamplingDecision::RecordAndSample;
        let mechanism = SamplingMechanism::LocalUserTraceSamplingRule;
        let sample_rate = 0.5;

        let attrs = sampler.add_dd_sampling_tags(&decision, mechanism, sample_rate, None);

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
                    assert_eq!(value_str, format!("-{}", mechanism.value()));
                    found_decision_maker = true;
                }
                SAMPLING_PRIORITY_TAG_KEY => {
                    // For LocalUserTraceSamplingRule with KEEP, it should be USER_KEEP
                    let priority_pair = SAMPLING_MECHANISM_TO_PRIORITIES.get(&mechanism).unwrap();
                    let expected_priority = priority_pair.0.value() as i64;

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
        let attrs_with_limit =
            sampler.add_dd_sampling_tags(&decision, mechanism, sample_rate, Some(rate_limit));

        // With rate limiting, there should be one more attribute
        assert_eq!(attrs_with_limit.len(), 4);

        // Check for rate limit attribute
        let mut found_limit = false;
        for attr in &attrs_with_limit {
            if attr.key.as_str() == SAMPLING_LIMIT_DECISION {
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
        let agent_mechanism = SamplingMechanism::AgentRateByService;
        let agent_rate = 0.75;

        let agent_attrs =
            sampler.add_dd_sampling_tags(&decision, agent_mechanism, agent_rate, None);

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
        let sampler = DatadogSampler::new(None, None);

        // Create empty slices for attributes and links
        let empty_attrs: &[KeyValue] = &[];
        let empty_links: &[opentelemetry::trace::Link] = &[];

        // Test with sampled parent context
        let parent_sampled = create_parent_context(true);
        let result_sampled = sampler.should_sample(
            Some(&parent_sampled),
            create_trace_id(),
            "span",
            &SpanKind::Client,
            empty_attrs,
            empty_links,
        );

        // Should inherit the sampling decision from parent
        assert_eq!(result_sampled.decision, SamplingDecision::RecordAndSample);
        assert!(result_sampled.attributes.is_empty());

        // Test with non-sampled parent context
        let parent_not_sampled = create_parent_context(false);
        let result_not_sampled = sampler.should_sample(
            Some(&parent_not_sampled),
            create_trace_id(),
            "span",
            &SpanKind::Client,
            empty_attrs,
            empty_links,
        );

        // Should inherit the sampling decision from parent
        assert_eq!(result_not_sampled.decision, SamplingDecision::Drop);
        assert!(result_not_sampled.attributes.is_empty());
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

        let sampler = DatadogSampler::new(Some(vec![rule]), None);

        // Create an empty slice for links
        let empty_links: &[opentelemetry::trace::Link] = &[];

        // Test with matching attributes
        let attrs = create_attributes("test-service", "resource", "prod");
        let result = sampler.should_sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs.as_slice(),
            empty_links,
        );

        // Should sample and add attributes
        assert_eq!(result.decision, SamplingDecision::RecordAndSample);
        assert!(!result.attributes.is_empty());

        // Test with non-matching attributes
        let attrs_no_match = create_attributes("other-service", "resource", "prod");
        let result_no_match = sampler.should_sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs_no_match.as_slice(),
            empty_links,
        );

        // Should still sample (default behavior when no rules match) and add attributes
        assert_eq!(result_no_match.decision, SamplingDecision::RecordAndSample);
        assert!(!result_no_match.attributes.is_empty());
    }

    #[test]
    fn test_should_sample_with_service_rates() {
        let mut sampler = DatadogSampler::new(None, None);

        // Add service rates
        let mut rates = HashMap::new();
        rates.insert("service:test-service,env:prod".to_string(), 1.0); // Always sample
        rates.insert("service:other-service,env:prod".to_string(), 0.0); // Never sample

        sampler.update_service_rates(rates);

        // Create an empty slice for links
        let empty_links: &[opentelemetry::trace::Link] = &[];

        // Test with service that should be sampled
        let attrs_sample = create_attributes("test-service", "resource", "prod");
        let result_sample = sampler.should_sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs_sample.as_slice(),
            empty_links,
        );

        // Should sample
        assert_eq!(result_sample.decision, SamplingDecision::RecordAndSample);

        // Test with service that should not be sampled
        let attrs_no_sample = create_attributes("other-service", "resource", "prod");
        let result_no_sample = sampler.should_sample(
            None,
            create_trace_id(),
            "span",
            &SpanKind::Client,
            attrs_no_sample.as_slice(),
            empty_links,
        );

        // Should not sample
        assert_eq!(result_no_sample.decision, SamplingDecision::Drop);
    }

    #[test]
    fn test_from_json() {
        // Create a JSON configuration string
        let config_json = r#"
        {
            "rules": [
                {
                    "sample_rate": 0.5,
                    "service": "test-service",
                    "name": "test-span",
                    "provenance": "customer"
                }
            ],
            "rate_limit": 200
        }
        "#;

        // Create a sampler from the JSON
        let sampler = DatadogSampler::from_json(config_json).unwrap();

        // Verify the configuration was applied
        assert_eq!(sampler.rules.len(), 1);
        assert_eq!(sampler.rules[0].sample_rate, 0.5);
        assert_eq!(sampler.rules[0].service, Some("test-service".to_string()));
        assert_eq!(sampler.rules[0].name, Some("test-span".to_string()));
        assert_eq!(sampler.rules[0].provenance, "customer");
    }
}
