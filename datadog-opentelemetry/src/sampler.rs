// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::{constants::SAMPLING_DECISION_MAKER_TAG_KEY, Config};
use dd_trace_sampling::DatadogSampler;
use opentelemetry::trace::TraceContextExt;
use opentelemetry_sdk::{trace::ShouldSample, Resource};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{span_processor::RegisterTracePropagationResult, TraceRegistry};

#[derive(Debug, Clone)]
pub struct Sampler {
    sampler: DatadogSampler,
    trace_registry: Arc<TraceRegistry>,
}

impl Sampler {
    pub fn new(
        cfg: &Config,
        resource: Arc<RwLock<Resource>>,
        trace_registry: Arc<TraceRegistry>,
    ) -> Self {
        let rules = cfg
            .trace_sampling_rules()
            .iter()
            .map(|r| {
                dd_trace_sampling::SamplingRule::new(
                    r.sample_rate,
                    r.service.clone(),
                    r.name.clone(),
                    r.resource.clone(),
                    Some(r.tags.clone()),
                    Some(r.provenance.clone()),
                )
            })
            .collect::<Vec<_>>();
        let sampler =
            dd_trace_sampling::DatadogSampler::new(rules, cfg.trace_rate_limit(), resource);
        Self {
            sampler,
            trace_registry,
        }
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
        let result = self.sampler.sample(
            parent_context
                .filter(|c| c.has_active_span())
                .map(|c| c.span().span_context().is_sampled()),
            trace_id,
            name,
            span_kind,
            attributes,
        );
        if let Some(trace_root_info) = &result.trace_root_info {
            match self.trace_registry.register_trace_propagation_data(
                trace_id.to_bytes(),
                trace_root_info.decision,
                None,
                // TODO(paullgdc): This is here so the injector adds the t.dm tag to
                // tracecontext. The injector should probably inject it from
                // the trace propagation data instead of tags.
                Some(HashMap::from_iter([(
                    SAMPLING_DECISION_MAKER_TAG_KEY.to_string(),
                    trace_root_info.decision.mechanism.to_cow().into_owned(),
                )])),
            ) {
                RegisterTracePropagationResult::Existing(sampling_decision) => {
                    return opentelemetry::trace::SamplingResult {
                        decision: if sampling_decision.priority.is_keep() {
                            opentelemetry::trace::SamplingDecision::RecordAndSample
                        } else {
                            opentelemetry::trace::SamplingDecision::RecordOnly
                        },
                        attributes: Vec::new(),
                        trace_state: parent_context
                            .map(|c| c.span().span_context().trace_state().clone())
                            .unwrap_or_default(),
                    }
                }
                RegisterTracePropagationResult::New => {}
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
    use dd_trace::configuration::SamplingRuleConfig;
    use opentelemetry::{
        trace::{SamplingDecision, SpanContext, SpanKind, TraceId, TraceState},
        Context, SpanId, TraceFlags,
    };
    use opentelemetry_sdk::trace::ShouldSample;
    use std::env;

    #[test]
    fn test_create_sampler_with_sampling_rules() {
        // Build a fresh config to pick up the env var
        let mut config = Config::builder();
        config.set_trace_sampling_rules(vec![SamplingRuleConfig {
            sample_rate: 0.5,
            service: Some("test-service".to_string()),
            name: None,
            resource: None,
            tags: HashMap::new(),
            provenance: "customer".to_string(),
        }]);
        let config = config.build();

        let test_resource = Arc::new(RwLock::new(Resource::builder().build()));
        let sampler = Sampler::new(&config, test_resource, Arc::new(TraceRegistry::new()));

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

        // Clean up environment
        env::remove_var("DD_TRACE_SAMPLING_RULES");
    }

    #[test]
    fn test_create_default_sampler() {
        // Create a default config (no rules, no specific rate limit)
        let config = Config::builder().build();

        let test_resource = Arc::new(RwLock::new(Resource::builder_empty().build()));
        let sampler = Sampler::new(&config, test_resource, Arc::new(TraceRegistry::new()));

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
        let config = Config::builder().build();

        let test_resource = Arc::new(RwLock::new(Resource::builder_empty().build()));
        let sampler = Sampler::new(&config, test_resource, Arc::new(TraceRegistry::new()));

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
