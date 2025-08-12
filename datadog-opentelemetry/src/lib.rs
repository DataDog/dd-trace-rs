// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod ddtrace_transform;
mod sampler;
mod span_exporter;
mod span_processor;
mod text_map_propagator;
mod trace_id;

use std::sync::{Arc, Mutex, RwLock};

use dd_trace::configuration::RemoteConfigUpdate;
use opentelemetry::{Key, KeyValue, Value};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use sampler::Sampler;
use span_processor::{DatadogSpanProcessor, TraceRegistry};
use text_map_propagator::DatadogPropagator;

// Type alias to simplify complex callback type
type SamplerCallback = Arc<Box<dyn Fn(&[dd_trace::SamplingRuleConfig]) + Send + Sync>>;

/// Initialize the Datadog OpenTelemetry exporter.
///
/// This function sets up the global OpenTelemetry SDK provider for compatibility with datadog.
///
/// # Usage
/// ```rust
/// use dd_trace::Config;
/// use opentelemetry_sdk::trace::TracerProviderBuilder;
///
/// // This picks up env var configuration and other datadog configuration sources
/// let datadog_config = Config::builder().build();
///
/// datadog_opentelemetry::init_datadog(
///     datadog_config,
///     TracerProviderBuilder::default(), // Pass any opentelemetry specific configuration here
///     // .with_max_attributes_per_span(max_attributes)
///     None,
/// );
/// ```
pub fn init_datadog(
    config: dd_trace::Config,
    // TODO(paullgdc): Should we take a builder or create it ourselves?
    // because some customer might want to set max_<things>_per_span using
    // the builder APIs
    // Or maybe we need a builder API called DatadogDistribution that takes
    // all parameters and has an install method?
    tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
    resource: Option<Resource>,
) -> SdkTracerProvider {
    let (tracer_provider, propagator) = make_tracer(config, tracer_provider_builder, resource);

    opentelemetry::global::set_text_map_propagator(propagator);
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    tracer_provider
}

/// Create an instance of the tracer provider
fn make_tracer(
    config: dd_trace::Config,
    mut tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
    resource: Option<Resource>,
) -> (SdkTracerProvider, DatadogPropagator) {
    let registry = Arc::new(TraceRegistry::new());
    let resource_slot = Arc::new(RwLock::new(Resource::builder_empty().build()));
    let sampler = Sampler::new(&config, resource_slot.clone(), registry.clone());

    let agent_response_handler = sampler.on_agent_response();

    let dd_resource = create_dd_resource(resource.unwrap_or(Resource::builder().build()), &config);
    tracer_provider_builder = tracer_provider_builder.with_resource(dd_resource);
    let propagator = DatadogPropagator::new(&config, registry.clone());

    // Get sampler callback before moving sampler into tracer provider
    let sampler_callback = if config.remote_config_enabled() {
        Some(sampler.on_rules_update())
    } else {
        None
    };

    let span_processor = DatadogSpanProcessor::new(
        config.clone(),
        registry.clone(),
        resource_slot.clone(),
        Some(agent_response_handler),
    );
    let tracer_provider = tracer_provider_builder
        .with_span_processor(span_processor)
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator)
        .build();

    // Initialize remote configuration client if enabled
    if config.remote_config_enabled() {
        // Create a mutable config that can be updated by remote config
        let config_arc = Arc::new(config);
        let mutable_config = Arc::new(Mutex::new(config_arc.as_ref().clone()));

        // Add sampler callback to the config before creating the remote config client
        if let Some(sampler_callback) = sampler_callback {
            let sampler_callback = Arc::new(sampler_callback);
            let sampler_callback_clone: SamplerCallback = sampler_callback.clone();
            mutable_config.lock().unwrap().add_remote_config_callback(
                "datadog_sampler_on_rules_update".to_string(),
                move |update| match update {
                    RemoteConfigUpdate::SamplingRules(rules) => {
                        sampler_callback_clone(rules);
                    }
                },
            );
        }

        // Create remote config client with mutable config
        let mutable_config = Arc::new(Mutex::new(config_arc.as_ref().clone()));
        if let Ok(client) =
            dd_trace::configuration::remote_config::RemoteConfigClient::new(mutable_config)
        {
            // Start the client in background
            let _handle = client.start();
            dd_trace::dd_debug!("RemoteConfigClient: Started remote configuration client");
        } else {
            dd_trace::dd_debug!("RemoteConfigClient: Failed to create remote config client");
        }
    }

    (tracer_provider, propagator)
}

fn merge_resource<I: IntoIterator<Item = (Key, Value)>>(
    base: Option<Resource>,
    additional: I,
) -> Resource {
    let mut builder = opentelemetry_sdk::Resource::builder_empty();
    if let Some(base) = base {
        if let Some(schema_url) = base.schema_url() {
            builder = builder.with_schema_url(
                base.iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
                schema_url.to_string(),
            );
        } else {
            builder = builder.with_attributes(
                base.iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            );
        }
    }
    builder = builder.with_attributes(additional.into_iter().map(|(k, v)| KeyValue::new(k, v)));
    builder.build()
}

fn create_dd_resource(resource: Resource, cfg: &dd_trace::Config) -> Resource {
    let otel_service_name: Option<Value> = resource.get(&Key::from_static_str(SERVICE_NAME));
    if otel_service_name.is_none() || otel_service_name.unwrap().as_str() == "unknown_service" {
        // If the OpenTelemetry service name is not set or is "unknown_service",
        // we override it with the Datadog service name.
        merge_resource(
            Some(resource),
            [(
                Key::from_static_str(SERVICE_NAME),
                Value::from(cfg.service().to_string()),
            )],
        )
    } else if !cfg.service_is_default() {
        // If the service is configured, we override the OpenTelemetry service name
        merge_resource(
            Some(resource),
            [(
                Key::from_static_str(SERVICE_NAME),
                Value::from(cfg.service().to_string()),
            )],
        )
    } else {
        // If the service is not configured, we keep the OpenTelemetry service name
        resource
    }
}

#[cfg(feature = "test-utils")]
pub fn make_test_tracer(
    config: dd_trace::Config,
    tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
) -> (SdkTracerProvider, DatadogPropagator) {
    make_tracer(config, tracer_provider_builder, None)
}
