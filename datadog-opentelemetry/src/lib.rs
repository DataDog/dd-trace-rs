// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

mod span_conversion;
mod span_exporter;

use opentelemetry_sdk::trace::SdkTracerProvider;
// TODO(paullgdc): Should we export this or just the setup function?
pub use span_exporter::DatadogExporter;

/// Initialize the Datadog OpenTelemetry exporter.
///
/// This function sets up the global OpenTelemetry SDK provider for compatibility with datadog.
///
/// # Usage
/// ```rust
/// use opentelemetry_sdk::trace::TracerProviderBuilder;
/// use dd_trace::Config;
///
/// // This picks up env var configuration and other datadog configuration sources
/// let datadog_config = Config::default();
///
/// datadog_opentelemetry::init_datadog(
///     datadog_config,
///     TracerProviderBuilder::default()
///      // Pass any opentelemetry specific configuration here
///      // .with_max_attributes_per_span(max_attributes)
/// )
/// ```
pub fn init_datadog(
    cfg: dd_trace::Config,
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

    let tracer_provider = tracer_provider_builder
        .with_batch_exporter(DatadogExporter::new(cfg).unwrap())
        // TODO: hookup additional components
        // .with_id_generator(id_generator)
        // .with_sampler(sampler)
        .build();
    opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    tracer_provider
}
