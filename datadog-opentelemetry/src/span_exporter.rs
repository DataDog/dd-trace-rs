// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{pin::Pin, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use libdd_data_pipeline::{
    trace_buffer::{Export, TraceBuffer, TraceBufferConfig, TraceBufferError, TraceChunk},
    trace_exporter::{
        agent_response::AgentResponse, error::TraceExporterError, TelemetryConfig,
        TraceExporterOutputFormat,
    },
};
use libdd_shared_runtime::SharedRuntime;
use opentelemetry_sdk::{trace::SpanData, Resource};

use crate::{configuration::Config, dd_debug, dd_error, ddtrace_transform, mappings::CachedConfig};

pub type QueueMetricsFetcher = libdd_data_pipeline::trace_buffer::QueueMetricsFetcher<SpanData>;

pub struct DatadogExporter {
    trace_buffer: TraceBuffer<SpanData>,
    runtime: Arc<SharedRuntime>,
    otel_resource: Arc<ArcSwap<Resource>>,
}

impl DatadogExporter {
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: Arc<Config>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    ) -> Self {
        let otel_resource = Arc::new(ArcSwap::new(Arc::new(Resource::builder_empty().build())));
        let runtime = Arc::new(
            SharedRuntime::new().expect("failed to create SharedRuntime for trace exporter"),
        );

        let mut builder = libdd_data_pipeline::trace_exporter::TraceExporterBuilder::default();
        builder
            .set_url(&config.trace_agent_url())
            .set_dogstatsd_url(&config.dogstatsd_agent_url())
            .set_tracer_version(config.tracer_version())
            .set_language(config.language())
            .set_language_version(config.language_version())
            .set_service(&config.service())
            .set_output_format(TraceExporterOutputFormat::V04)
            .set_shared_runtime(runtime.clone())
            .enable_health_metrics()
            .enable_agent_rates_payload_version();

        if config.trace_partial_flush_enabled() {
            builder.set_client_computed_top_level();
        }
        if config.trace_stats_computation_enabled() {
            builder.enable_stats(Duration::from_secs(10));
        }
        if let Some(env) = config.env() {
            builder.set_env(env);
        }
        if let Some(version) = config.version() {
            builder.set_app_version(version);
        }
        if config.telemetry_enabled() {
            builder.enable_telemetry(TelemetryConfig {
                heartbeat: (config.telemetry_heartbeat_interval() * 1000.0) as u64,
                runtime_id: Some(config.runtime_id().to_string()),
                debug_enabled: false,
            });
        }

        // Create the TraceBuffer + worker
        let (trace_buffer, worker) = TraceBuffer::new(
            TraceBufferConfig::new()
                .synchronous_export(config.trace_writer_synchronous_write())
                .synchronous_export_timeout(Some(config.trace_writer_synchronous_timeout()))
                .max_flush_interval(config.trace_writer_max_flush_interval()),
            // Build the response handler that bridges the old callback API
            Box::new(
                move |result: Result<AgentResponse, TraceExporterError>| match result {
                    Ok(AgentResponse::Unchanged) => {}
                    Ok(AgentResponse::Changed { body }) => {
                        if let Some(ref handler) = agent_response_handler {
                            (handler)(&body);
                        }
                    }
                    Err(e) => log_trace_exporter_error(&e),
                },
            ),
            // Build the export operation
            Box::new(MapperExporter {
                trace_exporter: builder
                    .build::<libdd_capabilities_impl::NativeCapabilities>()
                    .expect("failed to build TraceExporter"),
                otel_resource: arc_swap::Cache::new(otel_resource.clone()),
                cached_config: CachedConfig::new(&config),
                config: config.clone(),
            }),
        );

        let _ = runtime
            .spawn_worker(worker, true)
            .expect("failed to spawn TraceExporterWorker");

        DatadogExporter {
            trace_buffer,
            runtime,
            otel_resource,
        }
    }

    pub fn queue_metrics(&self) -> QueueMetricsFetcher {
        self.trace_buffer.queue_metrics()
    }

    pub fn send_chunk(&self, span_data: Vec<SpanData>) -> Result<(), TraceBufferError> {
        self.trace_buffer.send_chunk(span_data)
    }

    pub fn force_flush(&self) -> Result<(), TraceBufferError> {
        self.trace_buffer.force_flush()
    }

    /// Shut down the trace exporter runtime and wait for the worker to finish.
    pub fn shutdown(&self, timeout: Duration) -> Result<(), TraceBufferError> {
        self.runtime
            .shutdown(Some(timeout))
            .map_err(|_| TraceBufferError::TimedOut(timeout))?;
        self.trace_buffer.wait_shutdown_done(timeout)
    }

    pub fn set_resource(&self, r: Resource) {
        self.otel_resource.store(Arc::new(r));
    }
}

struct MapperExporter {
    trace_exporter: libdd_data_pipeline::trace_exporter::TraceExporter<
        libdd_capabilities_impl::NativeCapabilities,
    >,
    otel_resource: arc_swap::cache::Cache<
        Arc<arc_swap::ArcSwap<opentelemetry_sdk::Resource>>,
        Arc<opentelemetry_sdk::Resource>,
    >,
    cached_config: CachedConfig,
    config: Arc<Config>,
}

impl std::fmt::Debug for MapperExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapperExporter").finish()
    }
}

impl Export<SpanData> for MapperExporter {
    fn export_trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<SpanData>>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<AgentResponse, TraceExporterError>> + Send + '_,
        >,
    > {
        // Do all the OTel->DD conversion synchronously (before the async boundary)
        // so that borrows into `trace_chunks` don't need to cross an await point.
        let resource = self.otel_resource.load();
        let trace_chunks = trace_chunks
            .iter()
            .map(|chunk| -> Vec<_> {
                ddtrace_transform::otel_trace_chunk_to_dd_trace_chunk(
                    &self.cached_config,
                    chunk,
                    resource,
                )
            })
            .collect::<Vec<_>>();

        let services = trace_chunks
            .iter()
            .flatten()
            .map(|s| s.service.as_str())
            .filter(|s| !s.is_empty() && *s != "otlpresourcenoservicename");
        self.config.add_extra_services(services);

        let agent_response = self.trace_exporter.send_trace_chunks(trace_chunks);
        Box::pin(async move { agent_response })
    }
}

#[track_caller]
fn log_trace_exporter_error(e: &TraceExporterError) {
    use libdd_data_pipeline::trace_exporter::error;
    match e {
        // Exceptional errors
        TraceExporterError::Builder(e) => {
            dd_error!("DatadogExporter: Export error: Builder error: {}", e);
        }
        TraceExporterError::Internal(error::InternalErrorKind::InvalidWorkerState(state)) => {
            dd_error!(
                "DatadogExporter: Export error: Internal error: Invalid worker state: {}",
                state
            );
        }

        // Runtime errors
        TraceExporterError::Deserialization(e) => {
            dd_debug!(
                "DatadogExporter: Export error: Deserialization error: {}",
                e
            );
        }
        TraceExporterError::Io(error) => {
            dd_debug!("DatadogExporter: Export error: IO error: {}", error);
        }
        TraceExporterError::Network(e) => {
            dd_debug!("DatadogExporter: Export error: Network error: {}", e);
        }
        TraceExporterError::Request(e) => {
            dd_debug!("DatadogExporter: Export error: Request error: {}", e);
        }
        TraceExporterError::Serialization(error) => {
            dd_debug!(
                "DatadogExporter: Export error: Serialization error: {}",
                error
            );
        }
        TraceExporterError::Agent(error::AgentErrorKind::EmptyResponse) => {
            dd_debug!("DatadogExporter: Export error: Agent error: empty response");
        }
        TraceExporterError::Shutdown(error::ShutdownError::TimedOut(duration)) => {
            dd_debug!(
                "DatadogExporter: Export error: Shutdown error: timed out after {}ms",
                duration.as_millis()
            );
        }
        TraceExporterError::Telemetry(e) => {
            dd_debug!(
                "DatadogExporter: Export error: Instrumentation telemetry error: {}",
                e
            );
        }
    };
}
