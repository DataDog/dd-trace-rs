// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod ddtrace_transform;
mod sampler;
mod span_exporter;
mod span_processor;
mod text_map_propagator;
mod trace_id;

use std::sync::{Arc, RwLock};

use dd_trace::telemetry::init_telemetry;
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
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
    init_telemetry(&config, None);

    let (tracer_provider, propagator) = make_tracer(config, tracer_provider_builder, None);

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

    if let Some(resource) = resource {
        tracer_provider_builder = tracer_provider_builder.with_resource(resource)
    }

    let propagator = DatadogPropagator::new(&config, registry.clone());

    let span_processor = DatadogSpanProcessor::new(config, registry.clone(), resource_slot.clone());
    let tracer_provider = tracer_provider_builder
        .with_span_processor(span_processor)
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator)
        .build();

    (tracer_provider, propagator)
}

#[cfg(feature = "test-utils")]
pub fn make_test_tracer(
    config: dd_trace::Config,
    tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
) -> (SdkTracerProvider, DatadogPropagator) {
    let resource = Resource::builder()
        .with_attribute(opentelemetry::KeyValue::new(
            "service.name",
            config.service().to_string(),
        ))
        .build();
    make_tracer(config, tracer_provider_builder, Some(resource))
}
