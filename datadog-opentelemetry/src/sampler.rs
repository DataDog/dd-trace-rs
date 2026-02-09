// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog OTel Sampler

use opentelemetry::trace::{TraceContextExt, TraceState};
use opentelemetry_sdk::{trace::ShouldSample, Resource};
use std::sync::{Arc, RwLock};

use crate::{
    core::{
        configuration::Config, constants::SAMPLING_DECISION_MAKER_TAG_KEY,
        sampling::SamplingDecision,
    },
    sampling::{DatadogSampler, SamplingRule, SamplingRulesCallback},
    span_processor::{RegisterTracePropagationResult, TracePropagationData},
    text_map_propagator::{self, DatadogExtractData},
    TraceRegistry,
};

/// OpenTelemetry sampler implementation for Datadog tracing.
///
/// Implements the `ShouldSample` trait to make sampling decisions for traces based on
/// Datadog's sampling rules, rate limits, and service-based sampling rates.
#[derive(Debug, Clone)]
pub struct Sampler {
    sampler: DatadogSampler,
    trace_registry: Option<TraceRegistry>,
    cfg: Arc<Config>,
}

impl Sampler {
    /// Creates a new Datadog sampler.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Configuration containing sampling rules and rate limits
    /// * `resource` - OpenTelemetry resource with service information
    /// * `trace_registry` - Optional trace registry for managing in-flight traces (None for
    ///   benchmarking)
    pub fn new(
        cfg: Arc<Config>,
        resource: Arc<RwLock<Resource>>,
        // This is an Option to allow benchmarking different parts of sampling
        trace_registry: Option<TraceRegistry>,
    ) -> Self {
        let rules = SamplingRule::from_configs(cfg.trace_sampling_rules().to_vec());
        let sampler = DatadogSampler::new(rules, cfg.trace_rate_limit(), resource);
        Self {
            cfg,
            sampler,
            trace_registry,
        }
    }

    /// Returns a callback for processing agent responses.
    ///
    /// The callback updates service-based sampling rates based on the agent's response.
    pub fn on_agent_response(&self) -> Box<dyn for<'a> Fn(&'a str) + Send + Sync> {
        self.sampler.on_agent_response()
    }

    /// Get the callback for updating sampling rules
    pub fn on_rules_update(&self) -> SamplingRulesCallback {
        self.sampler.on_rules_update()
    }
}

impl ShouldSample for Sampler {
    fn should_sample(
        &self,
        parent_context: Option<&opentelemetry::Context>,
        trace_id: opentelemetry::trace::TraceId,
        name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[opentelemetry::KeyValue],
        _links: &[opentelemetry::trace::Link],
    ) -> opentelemetry::trace::SamplingResult {
        // If the library has been disabled, we make every span take a Drop decision
        // This way they will not store any data (attributes, name, errors, ...) and will not be
        // passed to span processors
        if !self.cfg.enabled() {
            return opentelemetry::trace::SamplingResult {
                decision: opentelemetry::trace::SamplingDecision::Drop,
                attributes: vec![],
                trace_state: TraceState::NONE,
            };
        }

        // If we have a deferred sampling decision on the parent span, we ignored the parent
        // sampling decision and let the sampler decide.
        let is_parent_deferred = parent_context
            .map(|c| {
                c.span().span_context().trace_flags() == text_map_propagator::TRACE_FLAG_DEFERRED
            })
            .unwrap_or(false);

        let is_parent_sampled = parent_context
            .filter(|c| !is_parent_deferred && c.has_active_span())
            .map(|c| c.span().span_context().trace_flags().is_sampled());

        let result = self
            .sampler
            .sample(is_parent_sampled, trace_id, name, span_kind, attributes);
        let trace_propagation_data = if let Some(trace_root_info) = &result.trace_root_info {
            // If the parent was deferred, we try to merge propagation tags with what we extracted
            let (mut tags, origin) = if is_parent_deferred {
                if let Some(DatadogExtractData {
                    internal_tags,
                    origin,
                    ..
                }) = parent_context.and_then(|c| c.get())
                {
                    (Some(internal_tags.clone()), origin.clone())
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };
            let mechanism = trace_root_info.mechanism;
            tags.get_or_insert_default().insert(
                SAMPLING_DECISION_MAKER_TAG_KEY.to_string(),
                mechanism.to_cow().into_owned(),
            );

            Some(TracePropagationData {
                sampling_decision: SamplingDecision {
                    priority: Some(trace_root_info.priority),
                    mechanism: Some(mechanism),
                },
                origin,
                tags,
            })
        } else if let Some(remote_ctx) =
            parent_context.filter(|c| c.span().span_context().is_remote())
        {
            if let Some(DatadogExtractData {
                sampling,
                origin,
                internal_tags,
                ..
            }) = remote_ctx.get()
            {
                let sampling_decision = SamplingDecision {
                    priority: sampling.priority,
                    mechanism: sampling.mechanism,
                };
                Some(TracePropagationData {
                    origin: origin.clone(),
                    sampling_decision,
                    tags: Some(internal_tags.clone()),
                })
            } else {
                None
            }
        } else {
            None
        };
        if let Some(trace_propagation_data) = trace_propagation_data {
            if let Some(trace_registry) = &self.trace_registry {
                match trace_registry.register_local_root_trace_propagation_data(
                    trace_id.to_bytes(),
                    trace_propagation_data,
                ) {
                    RegisterTracePropagationResult::Existing(sampling_decision) => {
                        return opentelemetry::trace::SamplingResult {
                            // If at this point the sampling decision is still None, we will
                            // end up sending the span to the agent without a sampling priority,
                            // which will later take a decision.
                            // So the span is marked as RecordAndSample because we treat it as such
                            decision: if sampling_decision.priority.is_none_or(|p| p.is_keep()) {
                                opentelemetry::trace::SamplingDecision::RecordAndSample
                            } else {
                                opentelemetry::trace::SamplingDecision::RecordOnly
                            },
                            attributes: Vec::new(),
                            trace_state: parent_context
                                .map(|c| c.span().span_context().trace_state().clone())
                                .unwrap_or_default(),
                        };
                    }
                    RegisterTracePropagationResult::New => {}
                }
            }
        }

        opentelemetry::trace::SamplingResult {
            decision: result.to_otel_decision(),
            attributes: result.to_dd_sampling_tags(),
            trace_state: parent_context
                .map(|c| c.span().span_context().trace_state().clone())
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::configuration::SamplingRuleConfig;
    use opentelemetry::{
        trace::{SamplingDecision, SpanContext, SpanKind, TraceId, TraceState},
        Context, SpanId, TraceFlags,
    };
    use opentelemetry_sdk::trace::ShouldSample;
    use std::collections::HashMap;

    #[test]
    fn test_create_sampler_with_sampling_rules() {
        // Build a fresh config to pick up the env var
        let config = Arc::new(
            Config::builder()
                .set_trace_sampling_rules(vec![SamplingRuleConfig {
                    sample_rate: 0.5,
                    service: Some("test-service".to_string()),
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "customer".to_string(),
                }])
                .build(),
        );

        let test_resource = Arc::new(RwLock::new(Resource::builder().build()));
        let sampler = Sampler::new(
            config.clone(),
            test_resource,
            Some(TraceRegistry::new(config)),
        );

        let trace_id_bytes = [1; 16];
        let trace_id = TraceId::from_bytes(trace_id_bytes);

        // Basic assertion: Check if the attributes added by the sampler are not empty,
        // implying some sampling logic (like adding priority tags) ran.
        assert!(
            !sampler
                .should_sample(None, trace_id, "test", &SpanKind::Client, &[], &[])
                .attributes
                .is_empty(),
            "Sampler should add attributes even if decision is complex"
        );
    }

    #[test]
    fn test_create_default_sampler() {
        // Create a default config (no rules, no specific rate limit)
        let config = Arc::new(Config::builder().build());

        let test_resource = Arc::new(RwLock::new(Resource::builder_empty().build()));
        let sampler = Sampler::new(
            config.clone(),
            test_resource,
            Some(TraceRegistry::new(config)),
        );

        let trace_id_bytes = [2; 16];
        let trace_id = TraceId::from_bytes(trace_id_bytes);

        // Verify the default sampler behavior
        let result = sampler.should_sample(None, trace_id, "test", &SpanKind::Client, &[], &[]);
        assert_eq!(
            result.decision,
            SamplingDecision::RecordAndSample,
            "Default sampler should record and sample by default"
        );
    }

    #[test]
    fn test_trace_state_propagation() {
        let config = Arc::new(Config::builder().build());

        let test_resource = Arc::new(RwLock::new(Resource::builder_empty().build()));
        let sampler = Sampler::new(
            config.clone(),
            test_resource,
            Some(TraceRegistry::new(config)),
        );

        let trace_id = TraceId::from_bytes([2; 16]);
        let span_id = SpanId::from_bytes([3; 8]);

        for is_sampled in [true, false] {
            let trace_state = TraceState::from_key_value([("test_key", "test_value")]).unwrap();
            let span_context = SpanContext::new(
                trace_id,
                span_id,
                if is_sampled {
                    TraceFlags::SAMPLED
                } else {
                    Default::default()
                },
                true,
                trace_state.clone(),
            );

            // Verify the sampler with a parent context
            let result = sampler.should_sample(
                Some(&Context::new().with_remote_span_context(span_context)),
                trace_id,
                "test",
                &SpanKind::Client,
                &[],
                &[],
            );
            assert_eq!(
                result.decision,
                if is_sampled {
                    SamplingDecision::RecordAndSample
                } else {
                    SamplingDecision::RecordOnly
                },
                "Sampler should respect parent context sampling decision"
            );
            assert_eq!(
                result.trace_state.header(),
                "test_key=test_value",
                "Sampler should propagate trace state from parent context"
            );
        }
    }
}
