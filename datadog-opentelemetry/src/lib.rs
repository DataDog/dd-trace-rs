// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod ddtrace_transform;
mod sampler;
mod span_exporter;
mod span_processor;
mod trace_id;
mod transform;

use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
pub use sampler::create_sampler_from_config;
pub use span_exporter::DatadogExporter;
use span_processor::DatadogSpanProcessor;
use std::sync::{Arc, RwLock};

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
///                                       // .with_max_attributes_per_span(max_attributes)
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
) -> SdkTracerProvider {
    // TODO: Setup datadog specific textmap propagator
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    // Create a shared resource for both the sampler and span processor
    let resource = Resource::builder_empty().build();
    let resource_arc = Arc::new(RwLock::new(resource));

    // Create the sampler with the shared resource (now passing the Arc directly)
    let sampler = sampler::create_sampler_from_config(&config, resource_arc.clone());

    // Create the span processor and share the resource
    let span_processor = DatadogSpanProcessor::new(config, resource_arc.clone());

    let tracer_provider = tracer_provider_builder
        .with_span_processor(span_processor)
        .with_sampler(sampler)
        .with_id_generator(trace_id::TraceidGenerator)
        .build();
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    tracer_provider
}

#[cfg(feature = "test-utils")]
/// Create a local instance of the tracer provider
pub fn make_tracer(
    config: dd_trace::Config,
    tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
) -> SdkTracerProvider {
    use opentelemetry::KeyValue;
    use opentelemetry_sdk::Resource;

    let resource_arc = Arc::new(RwLock::new(Resource::builder().build()));
    let sampler = sampler::create_sampler_from_config(&config, resource_arc.clone());

    tracer_provider_builder
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new("service.name", config.service().to_string()))
                .build(),
        )
        // Pass owned config to span_processor, then use the created sampler
        .with_span_processor(DatadogSpanProcessor::new(config, resource_arc.clone()))
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator)
        .build()
}
