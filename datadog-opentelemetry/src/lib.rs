// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod sampler;
mod span_conversion;
mod ddtrace_transform;
mod span_exporter;
mod span_processor;
mod trace_id;
mod transform;

use opentelemetry_sdk::trace::SdkTracerProvider;
pub use sampler::create_sampler_from_config;
pub use span_exporter::DatadogExporter;
use span_processor::DatadogSpanProcessor;

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

    // Create a DatadogSampler from config settings
    let sampler = sampler::create_sampler_from_config(&config);

    let tracer_provider = tracer_provider_builder
        .with_span_processor(DatadogSpanProcessor::new(config))
        .with_sampler(sampler)
        // TODO: hookup additional components
        // .with_id_generator(id_generator)
        .with_id_generator(trace_id::TraceidGenerator)
        // TODO: hookup additional components
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

    tracer_provider_builder
        .with_resource(
            Resource::builder()
                .with_attribute(KeyValue::new("service.name", config.service().to_string()))
                .build(),
        )
        .with_span_processor(DatadogSpanProcessor::new(config))
        .with_id_generator(trace_id::TraceidGenerator)
        // TODO: hookup additional components
        // .with_sampler(sampler)
        .build()
}
