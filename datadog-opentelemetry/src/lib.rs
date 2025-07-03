// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod ddtrace_transform;
mod sampler;
mod span_exporter;
mod span_processor;
mod text_map_propagator;
mod trace_id;

use std::sync::{Arc, RwLock};

use opentelemetry::{Key, KeyValue};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use sampler::Sampler;
use span_processor::{DatadogSpanProcessor, TraceRegistry};
use text_map_propagator::DatadogPropagator;

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
/// let datadog_config = Config::default();
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

    let dd_resource = create_dd_resource(
        resource.unwrap_or(Resource::builder().build()),
        config.service(),
    );
    tracer_provider_builder = tracer_provider_builder.with_resource(dd_resource);
    let propagator = DatadogPropagator::new(&config, registry.clone());

    let span_processor = DatadogSpanProcessor::new(config, registry.clone(), resource_slot.clone());
    let tracer_provider = tracer_provider_builder
        .with_span_processor(span_processor)
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator)
        .build();

    (tracer_provider, propagator)
}

fn create_dd_resource(resource: Resource, service_name: &str) -> Resource {
    let otel_service_name = resource.get(&Key::from_static_str(SERVICE_NAME));
    if !service_name.is_empty()
        && (otel_service_name.is_none() || otel_service_name.unwrap().as_str() == "unknown_service")
    {
        let mut builder = opentelemetry_sdk::Resource::builder_empty();
        if let Some(schema_url) = resource.schema_url() {
            builder = builder.with_schema_url(
                resource
                    .iter()
                    .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
                schema_url.to_string(),
            );
        } else {
            builder = builder.with_attributes(
                resource
                    .iter()
                    .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
            );
        }

        builder.with_service_name(service_name.to_string()).build()
    } else {
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
