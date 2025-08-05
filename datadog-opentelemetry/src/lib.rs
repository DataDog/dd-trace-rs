// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Datadog Opentelemetry
//!
//! A datadog layer of compatibility for the opentelemetry SDK
//! 
//! ## Usage
//! 
//! This is the minimal example to initialize the SDK.
//! 
//! This will read datadog and opentelemetry configuration from environment variables and other 
//! available sources.
//! And initialize and set up the tracer provider and the text map propagator globally.
//!
//! ```rust
//! # fn main() {
//! datadog_opentelemetry::tracing()
//!    .init();
//! # }
//! ```
//! 
//! It is also possible to customize the datadog configuration passed to the tracer provider.
//!
//! ```rust
//! // Custom datadog configuration
//! datadog_opentelemetry::tracing()
//!     .with_config(dd_trace::Config::builder()
//!         .set_service("my_service".to_string())
//!         .set_env("my_env".to_string())
//!         .set_version("1.0.0".to_string())
//!         .build()
//!     )
//!     .init();
//! ```
//!
//! Or to pass options to the OpenTelemetry SDK TracerProviderBuilder
//! ```rust
//! #[derive(Debug)]
//! struct MySpanProcessor;
//!
//! impl opentelemetry_sdk::trace::SpanProcessor for MySpanProcessor {
//!     fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {}
//!     fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {}
//!     fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult { Ok(()) }
//!     fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> opentelemetry_sdk::error::OTelSdkResult { Ok(()) }
//!     fn set_resource(&mut self, _resource: &opentelemetry_sdk::Resource) {}
//! }
//!
//! datadog_opentelemetry::tracing()
//!     .with_max_attributes_per_span(64)
//!     .with_span_processor(MySpanProcessor)
//!     .init();
//! ```

mod ddtrace_transform;
mod sampler;
mod span_exporter;
mod span_processor;
mod text_map_propagator;
mod trace_id;

use std::sync::{Arc, RwLock};

use opentelemetry::{Key, KeyValue, Value};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use sampler::Sampler;
use span_processor::{DatadogSpanProcessor, TraceRegistry};
use text_map_propagator::DatadogPropagator;

pub struct DatadogTracingBuilder {
    config: Option<dd_trace::Config>,
    resource: Option<opentelemetry_sdk::Resource>,
    tracer_provider: opentelemetry_sdk::trace::TracerProviderBuilder,
}

impl DatadogTracingBuilder {
    pub fn with_config(mut self, config: dd_trace::Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_resource(mut self, resource: opentelemetry_sdk::Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn init(self) -> SdkTracerProvider {
        let config = self
            .config
            .unwrap_or_else(|| dd_trace::Config::builder().build());
        let (tracer_provider, propagator) =
            make_tracer(config, self.tracer_provider, self.resource);

        opentelemetry::global::set_text_map_propagator(propagator);
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        tracer_provider
    }
}

impl DatadogTracingBuilder {
    // Methods forwarded to the otel tracer provider builder

    pub fn with_span_processor<T: opentelemetry_sdk::trace::SpanProcessor + 'static>(
        mut self,
        processor: T,
    ) -> Self {
        self.tracer_provider = self.tracer_provider.with_span_processor(processor);
        self
    }

    /// Specify the number of events to be recorded per span.
    pub fn with_max_events_per_span(mut self, max_events: u32) -> Self {
        self.tracer_provider = self.tracer_provider.with_max_events_per_span(max_events);
        self
    }

    /// Specify the number of attributes to be recorded per span.
    pub fn with_max_attributes_per_span(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_span(max_attributes);
        self
    }

    /// Specify the number of events to be recorded per span.
    pub fn with_max_links_per_span(mut self, max_links: u32) -> Self {
        self.tracer_provider = self.tracer_provider.with_max_links_per_span(max_links);
        self
    }

    /// Specify the number of attributes one event can have.
    pub fn with_max_attributes_per_event(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_event(max_attributes);
        self
    }

    /// Specify the number of attributes one link can have.
    pub fn with_max_attributes_per_link(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_link(max_attributes);
        self
    }

    /// Specify all limit via the span_limits
    pub fn with_span_limits(mut self, span_limits: opentelemetry_sdk::trace::SpanLimits) -> Self {
        self.tracer_provider = self.tracer_provider.with_span_limits(span_limits);
        self
    }
}

/// Initialize a new Datadog Tracing builder
///
/// # Usage
///
/// ```rust
/// // Default configuration
/// datadog_opentelemetry::tracing()
///     .init();
/// ```
///
/// It is also possible to customize the datadog configuration passed to the tracer provider.
///
/// ```rust
/// // Custom datadog configuration
/// datadog_opentelemetry::tracing()
///     .with_config(dd_trace::Config::builder()
///         .set_service("my_service".to_string())
///         .set_env("my_env".to_string())
///         .set_version("1.0.0".to_string())
///         .build()
///     )
///     .init();
/// ```
///
/// Or to pass options to the OpenTelemetry SDK TracerProviderBuilder
/// ```rust
/// #[derive(Debug)]
/// struct MySpanProcessor;
///
/// impl opentelemetry_sdk::trace::SpanProcessor for MySpanProcessor {
///     fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {}
///     fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {}
///     fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult { Ok(()) }
///     fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> opentelemetry_sdk::error::OTelSdkResult { Ok(()) }
///     fn set_resource(&mut self, _resource: &opentelemetry_sdk::Resource) {}
/// }
///
/// datadog_opentelemetry::tracing()
///     .with_max_attributes_per_span(64)
///     .with_span_processor(MySpanProcessor)
///     .init();
/// ```
pub fn tracing() -> DatadogTracingBuilder {
    DatadogTracingBuilder {
        config: None,
        tracer_provider: opentelemetry_sdk::trace::SdkTracerProvider::builder(),
        resource: None,
    }
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

    let span_processor = DatadogSpanProcessor::new(
        config,
        registry.clone(),
        resource_slot.clone(),
        Some(agent_response_handler),
    );
    let tracer_provider = tracer_provider_builder
        .with_span_processor(span_processor)
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator)
        .build();

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
