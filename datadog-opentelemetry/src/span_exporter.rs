// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use libdd_capabilities_impl::NativeCapabilities;
use libdd_data_pipeline::trace_exporter::{
    agent_response::AgentResponse, error::TraceExporterError, TelemetryConfig, TraceExporter,
    TraceExporterOutputFormat,
};
use opentelemetry_sdk::{trace::SpanData, Resource};

use crate::{
    configuration::Config,
    ddtrace_transform,
    exporter::{AsyncExporterError, AsyncTraceExporter, Exporter, TraceChunk},
    mappings::CachedConfig,
};

pub type QueueMetricsFetcher = crate::exporter::QueueMetricsFetcher<SpanData>;

pub struct DatadogExporter {
    exporter: crate::exporter::AsyncTraceExporter<SpanData>,
    otel_resource: Arc<ArcSwap<Resource>>,
}

impl DatadogExporter {
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: Arc<Config>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    ) -> Self {
        let otel_resource = Arc::new(ArcSwap::new(Arc::new(Resource::builder_empty().build())));
        let mut builder = libdd_data_pipeline::trace_exporter::TraceExporterBuilder::default();
        builder
            .set_url(&config.trace_agent_url())
            .set_dogstatsd_url(&config.dogstatsd_agent_url())
            .set_tracer_version(config.tracer_version())
            .set_language(config.language())
            .set_language_version(config.language_version())
            .set_service(&config.service())
            .set_output_format(TraceExporterOutputFormat::V04)
            .enable_health_metrics()
            .enable_agent_rates_payload_version();

        if config.trace_partial_flush_enabled() {
            builder.set_client_computed_top_level();
        }
        if config.trace_stats_computation_enabled() {
            builder.enable_stats(Duration::from_secs(10));
        }
        if config.client_side_stats_obfuscation() {
            builder.enable_client_side_stats_obfuscation();
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
        DatadogExporter {
            exporter: AsyncTraceExporter::new(
                crate::exporter::AsyncExporterConfig {
                    synchronous_writes: config.trace_writer_synchronous_write(),
                    synchronous_writes_timeout: Some(config.trace_writer_synchronous_timeout()),
                    max_flush_interval: config.trace_writer_max_flush_interval(),
                    ..Default::default()
                },
                agent_response_handler,
                Box::new(MapperExporter {
                    otel_resource: arc_swap::Cache::new(otel_resource.clone()),
                    cached_config: CachedConfig::new(&config),
                    config: config.clone(),
                }),
                builder,
            ),
            otel_resource,
        }
    }

    pub fn queue_metrics(&self) -> QueueMetricsFetcher {
        self.exporter.queue_metrics()
    }

    pub fn send_chunk(&self, span_data: Vec<SpanData>) -> Result<(), AsyncExporterError> {
        self.exporter.send_chunk(span_data)
    }

    pub fn force_flush(&self) -> Result<(), AsyncExporterError> {
        self.exporter.force_flush()
    }

    pub fn trigger_shutdown(&self) {
        self.exporter.trigger_shutdown()
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), AsyncExporterError> {
        self.exporter.wait_for_shutdown(timeout)
    }

    pub fn set_resource(&self, r: Resource) {
        self.otel_resource.store(Arc::new(r));
    }
}

struct MapperExporter {
    otel_resource: arc_swap::cache::Cache<
        Arc<arc_swap::ArcSwap<opentelemetry_sdk::Resource>>,
        Arc<opentelemetry_sdk::Resource>,
    >,
    cached_config: CachedConfig,
    config: Arc<Config>,
}

impl Exporter<SpanData> for MapperExporter {
    fn trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<SpanData>>,
        trace_exporter: &TraceExporter<NativeCapabilities>,
    ) -> Result<AgentResponse, TraceExporterError> {
        let resource = self.otel_resource.load();
        let trace_chunks = trace_chunks
            .iter()
            .map(|TraceChunk { chunk }| -> Vec<_> {
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

        let agent_response = trace_exporter.send_trace_chunks(trace_chunks)?;
        Ok(agent_response)
    }
}
