// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::Config;
use dd_trace_sampling::DatadogSampler;
use opentelemetry::trace::{TraceContextExt, TraceState};
use opentelemetry_sdk::{trace::ShouldSample, Resource};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{
    span_processor::{SamplingDecision, TracePropagationData},
    TraceRegistry,
};

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
            parent_context.map(|c| c.has_active_span() && c.span().span_context().is_sampled()),
            trace_id,
            name,
            span_kind,
            attributes,
        );
        if let Some(trace_root_info) = &result.trace_root_info {
            self.trace_registry.register_trace_propagation_data(
                trace_id.to_bytes(),
                TracePropagationData {
                    sampling_decision: Some(SamplingDecision {
                        decision: trace_root_info.sampling_priority(result.is_sampled).value(),
                        // TODO: unify these types with decision maker with the one in the span
                        // processor
                        decision_maker: trace_root_info.mechanism.value() as i8,
                    }),
                    origin: None,
                    // TODO(paullgdc): This is here so the injector adds the t.dm tag to tracecontext.
                    // The injector should probably inject it from the trace propagation data
                    // instead of tags.
                    tags: Some(HashMap::from_iter([(
                        "_dd.p.dm".to_string(),
                        format!("{}", -(trace_root_info.mechanism.value() as i32)),
                    )])),
                },
            );
        }

        opentelemetry::trace::SamplingResult {
            decision: result.to_otel_decision(),
            attributes: result.to_dd_sampling_tags(),
            trace_state: TraceState::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{SamplingDecision, SpanKind, TraceId};
    use opentelemetry_sdk::trace::ShouldSample;
    use std::env;

    #[test]
    fn test_create_sampler_with_sampling_rules() {
        // Set sampling rules through environment variable
        let sampling_rules_json =
            r#"[{"sample_rate":0.5,"service":"test-service","provenance":"customer"}]"#;
        env::set_var("DD_TRACE_SAMPLING_RULES", sampling_rules_json);

        // Build a fresh config to pick up the env var
        let config = Config::builder().build();

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
}
