// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! # Datadog Opentelemetry
//!
//! This library powers [Distributed Tracing](https://docs.datadoghq.com/tracing/). It provides OpenTelemetry API and SDK compatibility with Datadog-specific features and optimizations.
//!
//!
//! ## Usage
//!
//! The `datadog-opentelemetry` crate provides an easy to use override for the rust
//! opentelemetry-sdk.
//!
//! ### Installation
//!
//! Add to you Cargo.toml
//!
//! ```toml
//! datadog-opentelemetry = { version = "0.2.0" }
//! ```
//!
//! ### Tracing
//!
//! To trace functions, you can either use the `opentelemetry` crate's [API](https://docs.rs/opentelemetry/0.31.0/opentelemetry/trace/index.html) or the `tracing` crate [API](https://docs.rs/tracing/0.1.41/tracing/) with the `tracing-opentelemetry` [bridge](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/).
//!
//! ### Metrics
//!
//! To collect metrics, use the `opentelemetry` crate's [Metrics API](https://docs.rs/opentelemetry/0.31.0/opentelemetry/metrics/index.html).
//! For more details, see the [Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/api_support/rust/).
//!
//! ### Initialization
//!
//! The following examples will read datadog and opentelemetry configuration from environment
//! variables and other available sources, initialize and set up the tracer provider and the
//! distributed tracing propagators globally.
//!
//! #### Tracing API
//!
//! * Requires `tracing-subscriber` and `tracing`
//!
//! ```no_run
//! use opentelemetry::trace::TracerProvider;
//! use std::time::Duration;
//! use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
//!
//! // This picks up env var configuration and other datadog configuration sources
//! let tracer_provider = datadog_opentelemetry::tracing().init();
//!
//! tracing_subscriber::registry()
//!     .with(
//!         tracing_opentelemetry::layer()
//!             .with_tracer(tracer_provider.tracer("my_application_name")),
//!     )
//!     .init();
//!
//! tracer_provider
//!     .shutdown_with_timeout(Duration::from_secs(1))
//!     .expect("tracer shutdown error");
//! ```
//!
//! #### Opentelemetry API
//!
//! * requires `opentelemetry`
//!
//! ```no_run
//! use std::time::Duration;
//!
//! // This picks up env var configuration and other datadog configuration sources
//! let tracer_provider = datadog_opentelemetry::tracing().init();
//!
//! // Your code
//! // Now use standard OpenTelemetry APIs
//! use opentelemetry::global;
//! use opentelemetry::trace::Tracer;
//!
//! let tracer = global::tracer("my-service");
//! let span = tracer.start("my-operation");
//! // ... do work ...
//!
//! // Shutdown the tracer to flush the remaining data
//! tracer_provider
//!     .shutdown_with_timeout(Duration::from_secs(1))
//!     .expect("tracer shutdown error");
//! ```
//!
//! ### Configuration
//!
//! Configuration can be passed either:
//!
//! * Programmatically
//!
//! ```rust
//! use datadog_opentelemetry::configuration::Config;
//! let config = datadog_opentelemetry::configuration::Config::builder()
//!     .set_service("my_service".to_string())
//!     .set_env("prod".to_string())
//!     .build();
//! let tracer_provider = datadog_opentelemetry::tracing()
//!     .with_config(config)
//!     // this also accepts options for the Opentelemetry SDK builder
//!     .with_max_attributes_per_span(64)
//!     .init();
//! ```
//!
//! For advanced usage and configuration information, check out [`DatadogTracingBuilder`] and
//! [`configuration::ConfigBuilder`]
//!
//! #### Metrics API
//!
//! * Requires `opentelemetry` with metrics feature
//!
//! ```no_run
//! use std::time::Duration;
//!
//! // Enable metrics via environment variable
//! std::env::set_var("DD_METRICS_OTEL_ENABLED", "true");
//!
//! // Initialize metrics with default configuration
//! let meter_provider = datadog_opentelemetry::metrics().init().unwrap();
//!
//! // Use standard OpenTelemetry Metrics APIs
//! use opentelemetry::global;
//! use opentelemetry::metrics::Counter;
//! use opentelemetry::KeyValue;
//!
//! let meter = global::meter("my-service");
//! let counter: Counter<u64> = meter.u64_counter("requests").build();
//! counter.add(1, &[KeyValue::new("method", "GET")]);
//!
//! // Shutdown to flush remaining metrics
//! meter_provider.shutdown().unwrap();
//! ```
//!
//! For more details, see the [Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/api_support/rust/).
//!
//! * Through env variables
//!
//! ```bash
//! DD_METRICS_OTEL_ENABLED=true DD_SERVICE=my_service DD_ENV=prod cargo run
//! ```
//!
//! Or to pass options to the OpenTelemetry SDK TracerProviderBuilder
//! ```rust
//! # #[derive(Debug)]
//! # struct MySpanProcessor;
//! #
//! # impl opentelemetry_sdk::trace::SpanProcessor for MySpanProcessor {
//! #     fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
//! #     }
//! #     fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {}
//! #     fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
//! #         Ok(())
//! #     }
//! #     fn shutdown_with_timeout(
//! #         &self,
//! #         timeout: std::time::Duration,
//! #     ) -> opentelemetry_sdk::error::OTelSdkResult {
//! #         Ok(())
//! #     }
//! #     fn set_resource(&mut self, _resource: &opentelemetry_sdk::Resource) {}
//! # }
//! #
//! // Custom otel tracer sdk options
//! datadog_opentelemetry::tracing()
//!     .with_max_attributes_per_span(64)
//!     // Custom span processor
//!     .with_span_processor(MySpanProcessor)
//!     .init();
//! ```
//!
//! ## Support
//!
//! * MSRV: 1.84
//! * [opentelemetry](https://docs.rs/opentelemetry/0.31.0/opentelemetry/) version: 0.31
//! * [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.32.0/tracing_opentelemetry/)
//!   version: 0.32

// Public re-exports
pub use core::configuration;
pub use core::log;

#[cfg(feature = "test-utils")]
pub mod core;
#[cfg(feature = "test-utils")]
pub mod mappings;
#[cfg(feature = "test-utils")]
pub mod propagation;
#[cfg(feature = "test-utils")]
pub mod sampling;

#[cfg(not(feature = "test-utils"))]
pub(crate) mod core;
#[cfg(not(feature = "test-utils"))]
pub(crate) mod mappings;
#[cfg(not(feature = "test-utils"))]
pub(crate) mod propagation;
#[cfg(not(feature = "test-utils"))]
pub(crate) mod sampling;

mod ddtrace_transform;
pub mod metrics_exporter;
pub mod metrics_reader;
mod sampler;
mod span_exporter;
mod span_processor;
mod spans_metrics;
mod text_map_propagator;
mod trace_id;

use std::sync::{Arc, RwLock};

use opentelemetry::{Key, KeyValue, Value};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use opentelemetry_semantic_conventions::resource::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME};

use crate::{
    core::configuration::{Config, RemoteConfigUpdate},
    sampler::Sampler,
    span_processor::{DatadogSpanProcessor, TraceRegistry},
    text_map_propagator::DatadogPropagator,
};

pub struct DatadogTracingBuilder {
    config: Option<Config>,
    resource: Option<opentelemetry_sdk::Resource>,
    tracer_provider: opentelemetry_sdk::trace::TracerProviderBuilder,
}

impl DatadogTracingBuilder {
    /// Sets the datadog specific configuration
    ///
    /// Default: Config::builder().build()
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the resource passed to the SDK. See [opentelemetry_sdk::Resource]
    ///
    /// Default: Config::builder().build()
    pub fn with_resource(mut self, resource: opentelemetry_sdk::Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    /// Initializes the Tracer Provider, and the Text Map Propagator and install
    /// them globally
    pub fn init(self) -> SdkTracerProvider {
        let (tracer_provider, propagator) = self.init_local();

        opentelemetry::global::set_text_map_propagator(propagator);
        opentelemetry::global::set_tracer_provider(tracer_provider.clone());
        tracer_provider
    }

    /// Initialize the Tracer Provider, and the Text Map Propagator without doing a global
    /// installation
    ///
    /// You will need to set them up yourself, at a latter point if you want to use global tracing
    /// methods and library integrations
    ///
    /// # Example
    ///
    /// ```rust
    /// let (tracer_provider, propagator) = datadog_opentelemetry::tracing().init_local();
    ///
    /// opentelemetry::global::set_text_map_propagator(propagator);
    /// opentelemetry::global::set_tracer_provider(tracer_provider.clone());
    /// ```
    pub fn init_local(self) -> (SdkTracerProvider, DatadogPropagator) {
        let config = self.config.unwrap_or_else(|| Config::builder().build());
        make_tracer(Arc::new(config), self.tracer_provider, self.resource)
    }
}

impl DatadogTracingBuilder {
    // Methods forwarded to the otel tracer provider builder

    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_span_processor]
    pub fn with_span_processor<T: opentelemetry_sdk::trace::SpanProcessor + 'static>(
        mut self,
        processor: T,
    ) -> Self {
        self.tracer_provider = self.tracer_provider.with_span_processor(processor);
        self
    }

    /// Specify the number of events to be recorded per span.
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_max_events_per_span]
    pub fn with_max_events_per_span(mut self, max_events: u32) -> Self {
        self.tracer_provider = self.tracer_provider.with_max_events_per_span(max_events);
        self
    }

    /// Specify the number of attributes to be recorded per span.
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_max_attributes_per_span]
    pub fn with_max_attributes_per_span(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_span(max_attributes);
        self
    }

    /// Specify the number of events to be recorded per span.
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_max_links_per_span]
    pub fn with_max_links_per_span(mut self, max_links: u32) -> Self {
        self.tracer_provider = self.tracer_provider.with_max_links_per_span(max_links);
        self
    }

    /// Specify the number of attributes one event can have.
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_max_attributes_per_event]
    pub fn with_max_attributes_per_event(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_event(max_attributes);
        self
    }

    /// Specify the number of attributes one link can have.
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_max_attributes_per_link]
    pub fn with_max_attributes_per_link(mut self, max_attributes: u32) -> Self {
        self.tracer_provider = self
            .tracer_provider
            .with_max_attributes_per_link(max_attributes);
        self
    }

    /// Specify all limit via the span_limits
    /// See [opentelemetry_sdk::trace::TracerProviderBuilder::with_span_limits]
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
/// datadog_opentelemetry::tracing().init();
/// ```
///
/// It is also possible to customize the datadog configuration passed to the tracer provider.
///
/// ```rust
/// // Custom datadog configuration
/// datadog_opentelemetry::tracing()
///     .with_config(
///         datadog_opentelemetry::configuration::Config::builder()
///             .set_service("my_service".to_string())
///             .set_env("my_env".to_string())
///             .set_version("1.0.0".to_string())
///             .build(),
///     )
///     .init();
/// ```
///
/// Or to pass options to the OpenTelemetry SDK TracerProviderBuilder
/// ```rust
/// # #[derive(Debug)]
/// # struct MySpanProcessor;
/// #
/// # impl opentelemetry_sdk::trace::SpanProcessor for MySpanProcessor {
/// #     fn on_start(&self, span: &mut opentelemetry_sdk::trace::Span, cx: &opentelemetry::Context) {
/// #     }
/// #     fn on_end(&self, span: opentelemetry_sdk::trace::SpanData) {}
/// #     fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
/// #         Ok(())
/// #     }
/// #     fn shutdown_with_timeout(
/// #         &self,
/// #         timeout: std::time::Duration,
/// #     ) -> opentelemetry_sdk::error::OTelSdkResult {
/// #         Ok(())
/// #     }
/// #     fn set_resource(&mut self, _resource: &opentelemetry_sdk::Resource) {}
/// # }
/// #
/// // Custom otel tracer sdk options
/// datadog_opentelemetry::tracing()
///     .with_max_attributes_per_span(64)
///     // Custom span processor
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
    config: Arc<Config>,
    mut tracer_provider_builder: opentelemetry_sdk::trace::TracerProviderBuilder,
    resource: Option<Resource>,
) -> (SdkTracerProvider, DatadogPropagator) {
    let registry = TraceRegistry::new(config.clone());
    let resource_slot = Arc::new(RwLock::new(Resource::builder_empty().build()));
    // Sampler only needs config for initialization (reads initial sampling rules)
    // Runtime updates come via config callback, so no need for shared config
    let sampler = Sampler::new(config.clone(), resource_slot.clone(), registry.clone());

    let agent_response_handler = sampler.on_agent_response();

    let dd_resource = create_dd_resource(resource.unwrap_or(Resource::builder().build()), &config);
    tracer_provider_builder = tracer_provider_builder.with_resource(dd_resource);
    let propagator = DatadogPropagator::new(config.clone(), registry.clone());

    if config.remote_config_enabled() {
        let sampler_callback = sampler.on_rules_update();

        config.set_sampling_rules_callback(move |update| match update {
            RemoteConfigUpdate::SamplingRules(rules) => {
                sampler_callback(rules);
            }
        });
    };

    let mut tracer_provider_builder = tracer_provider_builder
        .with_sampler(sampler) // Use the sampler created above
        .with_id_generator(trace_id::TraceidGenerator);
    if config.enabled() {
        let span_processor = DatadogSpanProcessor::new(
            config.clone(),
            registry.clone(),
            resource_slot.clone(),
            Some(agent_response_handler),
        );
        tracer_provider_builder = tracer_provider_builder.with_span_processor(span_processor);
    }
    let tracer_provider = tracer_provider_builder.build();

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

fn create_dd_resource(resource: Resource, cfg: &Config) -> Resource {
    let otel_service_name: Option<Value> = resource.get(&Key::from_static_str(SERVICE_NAME));

    // Collect attributes to add
    let mut attributes = Vec::new();

    // Handle service name
    if otel_service_name.is_none() || otel_service_name.unwrap().as_str() == "unknown_service" {
        // If the OpenTelemetry service name is not set or is "unknown_service",
        // we override it with the Datadog service name.
        attributes.push((
            Key::from_static_str(SERVICE_NAME),
            Value::from(cfg.service().to_string()),
        ));
    } else if !cfg.service_is_default() {
        // If the service is configured, we override the OpenTelemetry service name
        attributes.push((
            Key::from_static_str(SERVICE_NAME),
            Value::from(cfg.service().to_string()),
        ));
    }

    // Handle environment - add it if configured and not already present
    if let Some(env) = cfg.env() {
        let otel_env: Option<Value> =
            resource.get(&Key::from_static_str(DEPLOYMENT_ENVIRONMENT_NAME));
        if otel_env.is_none() {
            attributes.push((
                Key::from_static_str(DEPLOYMENT_ENVIRONMENT_NAME),
                Value::from(env.to_string()),
            ));
        }
    }

    if attributes.is_empty() {
        // If no attributes to add, return the original resource
        resource
    } else {
        merge_resource(Some(resource), attributes)
    }
}

#[cfg(feature = "test-utils")]
pub fn make_test_tracer(shared_config: Arc<Config>) -> (SdkTracerProvider, DatadogPropagator) {
    make_tracer(
        shared_config,
        opentelemetry_sdk::trace::TracerProviderBuilder::default(),
        None,
    )
}

use opentelemetry_sdk::metrics::SdkMeterProvider;

/// Builder for Datadog Metrics with OTLP transport
pub struct DatadogMetricsBuilder {
    config: Option<Config>,
    resource: Option<Resource>,
    export_interval: Option<std::time::Duration>,
}

impl DatadogMetricsBuilder {
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_resource(mut self, resource: Resource) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn with_export_interval(mut self, interval: std::time::Duration) -> Self {
        self.export_interval = Some(interval);
        self
    }

    pub fn init(self) -> Result<SdkMeterProvider, String> {
        let (meter_provider, _) = self.init_local()?;
        opentelemetry::global::set_meter_provider(meter_provider.clone());
        Ok(meter_provider)
    }

    pub fn init_local(self) -> Result<(SdkMeterProvider, ()), String> {
        let config = self.config.unwrap_or_else(|| Config::builder().build());
        let meter_provider = crate::metrics_reader::create_meter_provider(
            Arc::new(config),
            self.resource,
            self.export_interval,
        )?;
        Ok((meter_provider, ()))
    }
}

/// Initialize a new Datadog Metrics builder with OTLP transport
///
/// Metrics are enabled separately from tracing via `DD_METRICS_OTEL_ENABLED=true`.
/// For more details, see the [Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/api_support/rust/).
///
/// # Usage
///
/// ```no_run
/// use std::time::Duration;
///
/// // Enable metrics via environment variable
/// std::env::set_var("DD_METRICS_OTEL_ENABLED", "true");
///
/// // Default configuration - exports metrics via OTLP/gRPC
/// let meter_provider = datadog_opentelemetry::metrics().init().unwrap();
///
/// // Use standard OpenTelemetry Metrics APIs
/// use opentelemetry::global;
/// use opentelemetry::metrics::Counter;
/// use opentelemetry::KeyValue;
///
/// let meter = global::meter("my-service");
/// let counter: Counter<u64> = meter.u64_counter("my_counter").build();
/// counter.add(1, &[KeyValue::new("key", "value")]);
///
/// // Shutdown to flush remaining metrics
/// meter_provider.shutdown().unwrap();
/// ```
///
/// With custom configuration:
///
/// ```no_run
/// use std::time::Duration;
///
/// std::env::set_var("DD_METRICS_OTEL_ENABLED", "true");
///
/// let meter_provider = datadog_opentelemetry::metrics()
///     .with_config(
///         datadog_opentelemetry::configuration::Config::builder()
///             .set_service("my_service".to_string())
///             .set_env("prod".to_string())
///             .build(),
///     )
///     .with_export_interval(Duration::from_secs(30))
///     .init()
///     .unwrap();
/// ```
pub fn metrics() -> DatadogMetricsBuilder {
    DatadogMetricsBuilder {
        config: None,
        resource: None,
        export_interval: None,
    }
}
