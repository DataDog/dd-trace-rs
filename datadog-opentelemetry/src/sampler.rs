// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0


use dd_trace::dd_warn;

use dd_trace_sampling::config::DatadogSamplerConfig;
use dd_trace_sampling::DatadogSampler;
use opentelemetry_sdk::Resource;
use std::sync::{Arc, RwLock};

/// Creates a DatadogSampler based on the given configuration
///
/// This function handles all the logic for creating a properly configured sampler:
/// - If sampling rules are defined via DD_TRACE_SAMPLING_RULES, they will be used
/// - Otherwise, a default sampler will be created using the rate limit configuration
///
/// This is exported as a utility function but typically users should not need to call it directly.
pub fn create_sampler_from_config(
    cfg: &dd_trace::Config,
    resource: Arc<RwLock<Resource>>,
) -> DatadogSampler {
    if let Some(rules_json) = cfg.trace_sampling_rules() {
        // If we have JSON rules, try to create a sampler from them
        match DatadogSamplerConfig::from_json_with_resource(rules_json, resource.clone()) {
            Ok(config) => {
                config.build_sampler()
            }
            Err(e) => {
                // Log error and fall back to default sampler
                dd_warn!("Error parsing sampling rules configuration: {}", e);
                create_default_sampler(cfg, resource)
            }
        }
    } else {
        // If no sampling config is provided, create a default sampler
        create_default_sampler(cfg, resource)
    }
}

// Helper function to create a sampler with default rules but with config rate limit
fn create_default_sampler(
    cfg: &dd_trace::Config,
    resource: Arc<RwLock<Resource>>,
) -> DatadogSampler {
    // Directly create the sampler with the provided resource and config options
    DatadogSampler::new(
        None, // No specific rules, so default behavior of DatadogSampler applies
        cfg.trace_rate_limit().map(|r| r as i32),
        resource, // Use the passed-in resource directly
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dd_trace::Config;
    use opentelemetry::trace::{SpanKind, TraceId};
    use opentelemetry_sdk::trace::ShouldSample;
    use opentelemetry_sdk::Resource;

    #[test]
    fn test_create_sampler_with_sampling_rules() {
        // Create a config with sampling rules
        let mut config_builder = Config::builder();
        config_builder.set_trace_sampling_rules(
            r#"{"rules":[{"sample_rate":0.5,"service":"test-service"}],"rate_limit":100}"#
                .to_string(),
        );
        let config = config_builder.build();

        // Create a resource for testing
        let resource = Resource::builder().build();

        // Create a sampler from the config
        let sampler = create_sampler_from_config(&config, Arc::new(RwLock::new(resource)));

        // Generate a simple trace ID for testing
        let trace_id_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let trace_id = TraceId::from_bytes(trace_id_bytes);

        // Verify the sampler was created (we can't directly check the rules)
        // In a real test environment, we could verify behavior by checking sampling decisions
        assert!(
            sampler
                .should_sample(None, trace_id, "test", &SpanKind::Client, &[], &[])
                .attributes
                .len()
                > 0
        );
    }

    #[test]
    fn test_create_default_sampler() {
        // Create a config with no sampling configuration
        let config = Config::builder().build();

        // Create a resource for testing
        let resource = Resource::builder().build();

        // Create a sampler from the config
        let sampler = create_sampler_from_config(&config, Arc::new(RwLock::new(resource)));

        // Generate a simple trace ID for testing
        let trace_id_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let trace_id = TraceId::from_bytes(trace_id_bytes);

        // Verify the default sampler was created
        let result = sampler.should_sample(None, trace_id, "test", &SpanKind::Client, &[], &[]);

        // The default sampler should always sample (rate 1.0)
        assert_eq!(
            result.decision,
            opentelemetry::trace::SamplingDecision::RecordAndSample
        );
    }
}
