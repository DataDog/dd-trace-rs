// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use dd_trace::Config;
use dd_trace_sampling::DatadogSampler;
use opentelemetry_sdk::Resource;
use std::sync::{Arc, RwLock};

/// Creates a DatadogSampler based on the given configuration
/// This function handles all the logic for creating a properly configured sampler:
pub fn create_sampler_from_config(cfg: &Config, resource: Arc<RwLock<Resource>>) -> DatadogSampler {
    cfg.build_datadog_sampler(resource)
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
        let sampler = create_sampler_from_config(&config, test_resource);

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

        let test_resource = Arc::new(RwLock::new(Resource::builder().build()));
        let sampler = create_sampler_from_config(&config, test_resource);

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
