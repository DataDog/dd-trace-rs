// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Datadog OTel SpanProcessor

use hashbrown::{hash_map, HashMap as BHashMap};
use std::{
    collections::HashMap,
    fmt::Debug,
    str::FromStr,
    sync::{Arc, RwLock},
};

use crate::{
    core::{
        configuration::{
            remote_config::{
                RemoteConfigClientError, RemoteConfigClientHandle, RemoteConfigClientWorker,
            },
            Config,
        },
        constants::SAMPLING_DECISION_MAKER_TAG_KEY,
        sampling::SamplingDecision,
        telemetry::init_telemetry,
        utils::WorkerError,
    },
    create_dd_resource, dd_debug, dd_error,
    span_exporter::{DatadogExporter, ExporterError},
    spans_metrics::{TelemetryMetricsCollector, TelemetryMetricsCollectorHandle},
    text_map_propagator::DatadogExtractData,
};
use opentelemetry::{
    global::ObjectSafeSpan,
    trace::{SpanContext, TraceContextExt, TraceState},
    Key, KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::{error::OTelSdkError, trace::SpanData};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

#[derive(Debug)]
struct Trace {
    local_root_span_id: [u8; 8],
    /// Root span will always be the first span in this vector if it is present
    finished_spans: Vec<SpanData>,
    open_span_count: usize,

    propagation_data: TracePropagationData,
}

#[derive(Debug, Clone)]
pub(crate) struct TracePropagationData {
    pub sampling_decision: SamplingDecision,
    pub origin: Option<String>,
    pub tags: Option<HashMap<String, String>>,
}

const EMPTY_PROPAGATION_DATA: TracePropagationData = TracePropagationData {
    origin: None,
    sampling_decision: SamplingDecision {
        priority: None,
        mechanism: None,
    },
    tags: None,
};

#[derive(Debug)]
struct InnerTraceRegistry {
    registry: BHashMap<[u8; 16], Trace>,
    metrics: TraceRegistryMetrics,
    config: Arc<Config>,
}

pub(crate) enum RegisterTracePropagationResult {
    Existing(SamplingDecision),
    New,
}

impl InnerTraceRegistry {
    fn register_local_root_trace_propagation_data(
        &mut self,
        trace_id: [u8; 16],
        propagation_data: TracePropagationData,
    ) -> RegisterTracePropagationResult {
        match self.registry.entry(trace_id) {
            hash_map::Entry::Occupied(mut occupied_entry) => {
                if occupied_entry
                    .get()
                    .propagation_data
                    .sampling_decision
                    .priority
                    .is_some()
                {
                    RegisterTracePropagationResult::Existing(
                        occupied_entry.get().propagation_data.sampling_decision,
                    )
                } else {
                    let trace = occupied_entry.get_mut();
                    trace.propagation_data = propagation_data;
                    RegisterTracePropagationResult::New
                }
            }
            hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(Trace {
                    local_root_span_id: [0; 8], /* This will be set when the first span is
                                                 * registered */
                    finished_spans: Vec::new(),
                    // We set the open span count to 1 to take into account the local root span
                    // then once we register it, we don't actually increment the open span count
                    // We have to do this because the tracing-otel bridge doesn't actually
                    // materialize spans until they are closed.
                    // Which means that if we don't consider the local root span as "opened" when we
                    // register it's propagation data, then child spans might be
                    // sent flushed prematurely
                    open_span_count: 1,
                    propagation_data,
                });
                self.metrics.trace_segments_created += 1;
                self.metrics.spans_created += 1;
                RegisterTracePropagationResult::New
            }
        }
    }

    /// Set the root span ID for a given trace ID.
    ///
    /// This should be paired, after a call to `register_local_root_trace_propagation_data`
    fn register_local_root_span(&mut self, trace_id: [u8; 16], root_span_id: [u8; 8]) {
        let trace = self.registry.entry(trace_id).or_insert_with(|| Trace {
            local_root_span_id: [0; 8], // This will be set when the first span is registered
            finished_spans: Vec::new(),
            open_span_count: 1,
            propagation_data: EMPTY_PROPAGATION_DATA,
        });
        if trace.local_root_span_id == [0; 8] {
            trace.local_root_span_id = root_span_id;
        } else {
            dd_debug!(
                "TraceRegistry.register_local_root_span: trace with trace_id={:?} already has a root span registered with root_span_id={:?}. Ignoring the new root_span_id={:?}",
                trace_id,
                trace.local_root_span_id,
                root_span_id
            );
        }
    }

    /// Register a new trace with the given trace ID and span ID.
    /// If the trace is already registered, increment the open span count.
    /// If the trace is not registered, create a new entry with the given trace ID
    fn register_span(
        &mut self,
        trace_id: [u8; 16],
        span_id: [u8; 8],
        propagation_data: TracePropagationData,
    ) {
        self.registry
            .entry(trace_id)
            .or_insert_with(|| {
                self.metrics.trace_segments_created += 1;
                Trace {
                    local_root_span_id: span_id,
                    finished_spans: Vec::new(),
                    open_span_count: 0,
                    propagation_data,
                }
            })
            .open_span_count += 1;
        self.metrics.spans_created += 1;
    }

    /// Finish a span with the given trace ID and span data.
    /// If the trace is finished (i.e., all spans are finished), return the full trace chunk.
    /// Otherwise, return None.
    ///
    /// This function tries to maintain the invariant that the first span of the trace chunk should
    /// be the local root span, since it makes processing latter easier.
    /// If the root span is not the first span, it will be swapped with the first span.
    ///
    /// # Bounding memory usage
    ///
    /// If partial flushing in not enabled traces with unfinished spans are kept forever in memory.
    /// This lead to unbounded memory usage, if new spans keep getting added to the trace.
    ///
    /// Otherwise we flush partial trace chunks when then contain more than the configured minimum
    /// count of spans
    fn finish_span(&mut self, trace_id: [u8; 16], span_data: SpanData) -> Option<Trace> {
        self.metrics.spans_finished += 1;
        if let hash_map::Entry::Occupied(mut slot) = self.registry.entry(trace_id) {
            let trace = slot.get_mut();
            let span = if !trace.finished_spans.is_empty()
                && span_data.span_context.span_id().to_bytes() == trace.local_root_span_id
            {
                std::mem::replace(&mut trace.finished_spans[0], span_data)
            } else {
                span_data
            };

            // Reserve enough space to store all currently open spans in the chunk,
            trace.finished_spans.reserve(trace.open_span_count);
            trace.finished_spans.push(span);

            trace.open_span_count = trace.open_span_count.saturating_sub(1);
            let partial_flush = self.config.trace_partial_flush_enabled()
                && trace.finished_spans.len() >= self.config.trace_partial_flush_min_spans();
            if partial_flush {
                self.metrics.trace_partial_flush_count += 1;
                let trace = Trace {
                    local_root_span_id: trace.local_root_span_id,
                    finished_spans: std::mem::take(&mut trace.finished_spans),
                    open_span_count: trace.open_span_count,
                    propagation_data: trace.propagation_data.clone(),
                };
                Some(trace)
            } else if trace.open_span_count == 0 {
                let trace = slot.remove();
                self.metrics.trace_segments_closed += 1;
                Some(trace)
            } else {
                None
            }
        } else {
            // if we somehow don't have the trace registered, we just flush the span...
            self.metrics.trace_segments_created += 1;
            self.metrics.trace_segments_closed += 1;

            dd_debug!(
                "TraceRegistry.finish_span: trace with trace_id={:?} has a finished span span_id={:?}, but hasn't been registered first. This is probably a bug.",
                u128::from_be_bytes(trace_id),
                u64::from_be_bytes(span_data.span_context.span_id().to_bytes())

            );
            Some(Trace {
                local_root_span_id: span_data.span_context.span_id().to_bytes(),
                finished_spans: vec![span_data],
                open_span_count: 0,
                propagation_data: EMPTY_PROPAGATION_DATA,
            })
        }
    }

    fn get_trace_propagation_data(&self, trace_id: [u8; 16]) -> &TracePropagationData {
        match self.registry.get(&trace_id) {
            Some(trace) => &trace.propagation_data,
            None => &EMPTY_PROPAGATION_DATA,
        }
    }

    fn get_metrics(&mut self) -> TraceRegistryMetrics {
        std::mem::take(&mut self.metrics)
    }
}

const TRACE_REGISTRY_SHARDS: usize = 64;

#[repr(align(128))]
#[derive(Debug, Clone)]
struct CachePadded<T>(T);

#[derive(Clone, Debug)]
/// A registry of traces that are currently running
///
/// This registry maintains the following information:
/// - The root span ID of the trace
/// - The finished spans of the trace
/// - The number of open spans in the trace
/// - The sampling decision of the trace
pub struct TraceRegistry {
    // Example:
    // inner: Arc<[CacheAligned<RwLock<InnerTraceRegistry>>; N]>;
    // to access a trace we do inner[hash(trace_id) % N].read()
    inner: Arc<[CachePadded<RwLock<InnerTraceRegistry>>; TRACE_REGISTRY_SHARDS]>,
    hasher: foldhash::fast::RandomState,
}

impl TraceRegistry {
    /// Creates a new trace registry.
    ///
    /// The registry uses sharding to minimize lock contention when multiple threads
    /// are creating and finishing spans concurrently.
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            inner: Arc::new(std::array::from_fn(|_| {
                CachePadded(RwLock::new(InnerTraceRegistry {
                    registry: BHashMap::new(),
                    metrics: TraceRegistryMetrics::default(),
                    config: config.clone(),
                }))
            })),
            hasher: foldhash::fast::RandomState::default(),
        }
    }

    fn get_shard(&self, trace_id: [u8; 16]) -> &RwLock<InnerTraceRegistry> {
        use std::hash::BuildHasher;
        let hash = self.hasher.hash_one(u128::from_ne_bytes(trace_id));
        let shard = hash as usize % TRACE_REGISTRY_SHARDS;
        &self.inner[shard].0
    }

    /// Register the trace propagation data for a given trace ID
    /// This increases the open span count for the trace by 1, but does not set the root span ID.
    /// You will then need to call `register_local_root_span` to set the root span ID
    ///
    /// If the trace is already registered with a non None sampling decision,
    /// it will return the existing sampling decision instead
    #[allow(private_interfaces)]
    pub fn register_local_root_trace_propagation_data(
        &self,
        trace_id: [u8; 16],
        propagation_data: TracePropagationData,
    ) -> RegisterTracePropagationResult {
        let mut inner = self
            .get_shard(trace_id)
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_local_root_trace_propagation_data(trace_id, propagation_data)
    }

    /// Set the root span ID for a given trace ID.
    /// This will also increment the open span count for the trace.
    /// If the trace is already registered, it will ignore the new root span ID and log a warning.
    pub fn register_local_root_span(&self, trace_id: [u8; 16], root_span_id: [u8; 8]) {
        let mut inner = self
            .get_shard(trace_id)
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_local_root_span(trace_id, root_span_id);
    }

    /// Register a new span with the given trace ID and span ID.
    #[allow(private_interfaces)]
    pub fn register_span(
        &self,
        trace_id: [u8; 16],
        span_id: [u8; 8],
        propagation_data: TracePropagationData,
    ) {
        let mut inner = self
            .get_shard(trace_id)
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_span(trace_id, span_id, propagation_data);
    }

    /// Finish a span with the given trace ID and span data.
    /// If the trace is finished (i.e., all spans are finished), return the full trace chunk to
    /// flush
    fn finish_span(&self, trace_id: [u8; 16], span_data: SpanData) -> Option<Trace> {
        let mut inner = self
            .get_shard(trace_id)
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.finish_span(trace_id, span_data)
    }

    /// Retrieves the trace propagation data for a given trace ID.
    ///
    /// Returns the sampling decision, origin, and internal tags associated with the trace.
    #[allow(private_interfaces)]
    pub fn get_trace_propagation_data(&self, trace_id: [u8; 16]) -> TracePropagationData {
        let inner = self
            .get_shard(trace_id)
            .read()
            .expect("Failed to acquire lock on trace registry");

        inner.get_trace_propagation_data(trace_id).clone()
    }

    /// Aggregates and returns metrics from all registry shards.
    ///
    /// Collects counters for spans created/finished, trace segments, and partial flushes
    /// across all shards in the registry.
    pub fn get_metrics(&self) -> TraceRegistryMetrics {
        let mut stats = TraceRegistryMetrics::default();
        for shard_idx in 0..TRACE_REGISTRY_SHARDS {
            let mut shard = self.inner[shard_idx].0.write().unwrap();
            let shard_stats = shard.get_metrics();
            stats.spans_created += shard_stats.spans_created;
            stats.spans_finished += shard_stats.spans_finished;
            stats.trace_segments_created += shard_stats.trace_segments_created;
            stats.trace_segments_closed += shard_stats.trace_segments_closed;
            stats.trace_partial_flush_count += shard_stats.trace_partial_flush_count;
        }
        stats
    }
}

/// Metrics collected by the trace registry.
///
/// Tracks the lifecycle of spans and traces through the registry, useful for
/// monitoring and debugging trace collection behavior.
#[derive(Default, Debug)]
pub struct TraceRegistryMetrics {
    /// Number of spans created and registered in the registry.
    pub spans_created: usize,
    /// Number of spans that have finished processing.
    pub spans_finished: usize,
    /// Number of trace segments created (complete or partial traces).
    pub trace_segments_created: usize,
    /// Number of trace segments closed and sent to the exporter.
    pub trace_segments_closed: usize,
    /// Number of times traces were partially flushed before completion.
    pub trace_partial_flush_count: usize,
}

pub(crate) struct DatadogSpanProcessor {
    registry: TraceRegistry,
    span_exporter: DatadogExporter,
    resource: Arc<RwLock<Resource>>,
    config: Arc<Config>,
    rc_client_handle: Option<RemoteConfigClientHandle>,
    telemetry_metrics_handle: Option<TelemetryMetricsCollectorHandle>,
}

impl std::fmt::Debug for DatadogSpanProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogSpanProcessor").finish()
    }
}

impl DatadogSpanProcessor {
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        config: Arc<Config>,
        registry: TraceRegistry,
        resource: Arc<RwLock<Resource>>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    ) -> Self {
        let rc_client_handle = if config.remote_config_enabled() && config.enabled() {
            RemoteConfigClientWorker::start(config.clone())
                .inspect_err(|e| {
                    dd_error!(
                        "RemoteConfigClientWorker.start: Failed to start remote config client: {}",
                        e
                    );
                })
                .ok()
        } else {
            None
        };
        let span_exporter = DatadogExporter::new(config.clone(), agent_response_handler);
        let telemetry_metrics_handle = config.telemetry_enabled().then(|| {
            TelemetryMetricsCollector::start(registry.clone(), span_exporter.queue_metrics())
        });

        Self {
            registry,
            span_exporter,
            resource,
            config,
            rc_client_handle,
            telemetry_metrics_handle,
        }
    }

    /// If SpanContext is remote, recover [`DatadogExtractData`] from parent context:
    /// - links generated during extraction are added to the root span as span links.
    /// - sampling decision, origin and tags are returned to be stored as Trace propagation data
    fn add_remote_links(
        &self,
        span: &mut opentelemetry_sdk::trace::Span,
        parent_ctx: &opentelemetry::Context,
    ) {
        if let Some(DatadogExtractData { links, .. }) = parent_ctx.get::<DatadogExtractData>() {
            links.iter().for_each(|link| {
                let link_ctx = SpanContext::new(
                    TraceId::from(link.trace_id as u128),
                    SpanId::from(link.span_id),
                    TraceFlags::new(link.flags.unwrap_or_default() as u8),
                    false, // TODO: dd SpanLink doesn't have the remote field...
                    link.tracestate
                        .as_ref()
                        .map(|ts| TraceState::from_str(ts).unwrap_or_default())
                        .unwrap_or_default(),
                );

                let attributes = match &link.attributes {
                    Some(attributes) => attributes
                        .iter()
                        .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
                        .collect(),
                    None => vec![],
                };

                span.add_link(link_ctx, attributes);
            });
        }
    }

    /// If [`Trace`] contains origin, tags or sampling_decision add them as attributes of the root
    /// span
    fn add_trace_propagation_data(&self, mut trace: Trace) -> Vec<SpanData> {
        let propagation_data = trace.propagation_data;
        let origin = propagation_data.origin.unwrap_or_default();

        for span in trace.finished_spans.iter_mut() {
            if span.span_context.span_id().to_bytes() == trace.local_root_span_id {
                if let Some(ref tags) = propagation_data.tags {
                    tags.iter().for_each(|(key, value)| {
                        span.attributes
                            .push(KeyValue::new(key.clone(), value.clone()))
                    });
                }
            }

            if !origin.is_empty() {
                span.attributes
                    .push(KeyValue::new("_dd.origin", origin.clone()));
            }

            // TODO: is this correct? What if _sampling_priority_v1 or _dd.p.dm were extracted?
            // they shouldn't be overridden
            if let Some(priority) = propagation_data.sampling_decision.priority {
                span.attributes.push(KeyValue::new(
                    "_sampling_priority_v1",
                    priority.into_i8() as i64,
                ));
            }

            if let Some(mechanism) = propagation_data.sampling_decision.mechanism {
                span.attributes.push(KeyValue::new(
                    SAMPLING_DECISION_MAKER_TAG_KEY,
                    mechanism.to_cow(),
                ));
            }
        }

        trace.finished_spans
    }
}

impl opentelemetry_sdk::trace::SpanProcessor for DatadogSpanProcessor {
    fn on_start(
        &self,
        span: &mut opentelemetry_sdk::trace::Span,
        parent_ctx: &opentelemetry::Context,
    ) {
        if !self.config.enabled() || !span.is_recording() || !span.span_context().is_valid() {
            return;
        }

        let trace_id = span.span_context().trace_id().to_bytes();
        let span_id = span.span_context().span_id().to_bytes();

        if parent_ctx.span().span_context().is_remote() {
            self.add_remote_links(span, parent_ctx);
            self.registry.register_local_root_span(trace_id, span_id);
        } else if !parent_ctx.has_active_span() {
            self.registry.register_local_root_span(trace_id, span_id);
        } else {
            self.registry
                .register_span(trace_id, span_id, EMPTY_PROPAGATION_DATA);
        }
    }

    fn on_end(&self, span: SpanData) {
        let trace_id = span.span_context.trace_id().to_bytes();

        let Some(mut trace) = self.registry.finish_span(trace_id, span) else {
            return;
        };

        if !self.config.enabled() {
            return;
        }

        if self.config.trace_partial_flush_enabled() {
            // TODO(paullgdc):
            // This is wrong, we should go over all span to find who has a different service name
            // than their parent yet this is complex to implement as there are cases
            // where we can't read the parent before finishing the child...
            // This tags only the local root as top level which is good enough in a lot of cases
            // though To make partial flushing enabled by default we should fix this
            // behaviour.
            let root_span = trace
                .finished_spans
                .iter_mut()
                .find(|s| s.span_context.span_id().to_bytes() == trace.local_root_span_id);
            if let Some(root_span) = root_span {
                root_span.attributes.push(KeyValue::new("_top_level", 1.0));
            }
        }

        // Add propagation data before exporting the trace
        let trace_chunk = self.add_trace_propagation_data(trace);
        if let Err(e) = self.span_exporter.export_chunk_no_wait(trace_chunk) {
            match e {
                ExporterError::Panic(p) => {
                    dd_error!("DatadogSpanProcessor.on_end message='Failed to export trace chunk' operation='DatadogExporter.export_chunk_no_wait' panic='{}'", p)
                }
                _ => dd_debug!(
                    "DatadogSpanProcessor.on_end message='Failed to export trace chunk' error='{}'",
                    exporter_error_to_otel(&e, "export_chunk_no_wait")
                ),
            }
        }
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.span_exporter
            .force_flush()
            .map_err(|e| exporter_error_to_otel(&e, "force_flush"))
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        let deadline = std::time::Instant::now() + timeout;

        // Trigger all tasks shutdown
        self.span_exporter.trigger_shutdown();
        if let Some(rc_client_handle) = &self.rc_client_handle {
            rc_client_handle.trigger_shutdown();
        };
        if let Some(telemetry_metrics_handle) = &self.telemetry_metrics_handle {
            telemetry_metrics_handle.trigger_shutdown();
        }

        // Wait fot all tasks to finish, keeping in mind how much time is left
        // since the beginning of the call
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        self.span_exporter.wait_for_shutdown(left).map_err(|e| {
            let e = match e {
                ExporterError::TimedOut(_) => ExporterError::TimedOut(timeout),
                _ => e,
            };
            exporter_error_to_otel(&e, "wait_for_shutdown")
        })?;

        if let Some(rc_client_handle) = &self.rc_client_handle {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            rc_client_handle
                .wait_for_shutdown(left)
                .map_err(|e| match e {
                    RemoteConfigClientError::HandleMutexPoisoned
                    | RemoteConfigClientError::WorkerPanicked(_)
                    | RemoteConfigClientError::InvalidAgentUri => {
                        opentelemetry_sdk::error::OTelSdkError::InternalFailure(format!(
                            "RemoteConfigClient.shutdown_with_timeout: {}",
                            e
                        ))
                    }
                    RemoteConfigClientError::ShutdownTimedOut => {
                        opentelemetry_sdk::error::OTelSdkError::Timeout(timeout)
                    }
                })?;
        }

        if let Some(telemetry_metrics_handle) = &self.telemetry_metrics_handle {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            telemetry_metrics_handle
                .wait_for_shutdown(left)
                .map_err(|e| match e {
                    WorkerError::ShutdownTimedOut => {
                        opentelemetry_sdk::error::OTelSdkError::Timeout(timeout)
                    }
                    WorkerError::HandleMutexPoisoned | WorkerError::WorkerPanicked(_) => {
                        opentelemetry_sdk::error::OTelSdkError::InternalFailure(format!(
                            "TelemetryMetricsCollector.shutdown_with_timeout: {}",
                            e
                        ))
                    }
                })?;
        }
        Ok(())
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        let dd_resource = create_dd_resource(resource.clone(), &self.config);
        if let Err(e) = self.span_exporter.set_resource(dd_resource.clone()) {
            let e = exporter_error_to_otel(&e, "set_resource");
            dd_error!(
                "DatadogSpanProcessor.set_resource message='Failed to set resource' error='{e}'",
            );
        }
        // set the shared resource in the DatadogSpanProcessor
        *self.resource.write().unwrap() = dd_resource.clone();

        // update config's service name and init telemetry once service name has been resolved
        let service_name = dd_resource
            .get(&Key::from_static_str(SERVICE_NAME))
            .map(|service_name| service_name.as_str().to_string());
        // Only set calculated service name if DD_SERVICE is default
        // and otel service name is not default
        if self.config.service_is_default()
            && service_name.is_some()
            && service_name.as_ref().unwrap().as_str() != self.config.service().to_string()
        {
            self.config.set_calculated_service_name(service_name);
        }
        init_telemetry(&self.config);
    }
}

fn exporter_error_to_otel(e: &ExporterError, operation: &str) -> OTelSdkError {
    match e {
        ExporterError::AlreadyShutdown => OTelSdkError::AlreadyShutdown,
        ExporterError::TimedOut(duration) => OTelSdkError::Timeout(*duration),
        ExporterError::MutexPoisoned => OTelSdkError::InternalFailure(format!(
            "DatadogExporter.{operation}: the sender mutex was poisonned"
        )),
        ExporterError::BatchFull(_) => {
            OTelSdkError::InternalFailure(format!("DatadogExporter.{operation}: unexpected error"))
        }
        ExporterError::Panic(_) => {
            OTelSdkError::InternalFailure(format!("DatadogExporter.{operation}: a panic happened"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::HashMap,
        hint::black_box,
        sync::{Arc, RwLock},
        thread,
        time::Duration,
    };

    use crate::core::{
        configuration::Config,
        sampling::{mechanism, priority, SamplingDecision},
    };
    use opentelemetry::{
        trace::{SpanContext, TraceFlags},
        SpanId, TraceId, {Key, KeyValue, Value},
    };
    use opentelemetry_sdk::{
        trace::{SpanData, SpanEvents, SpanLinks, SpanProcessor},
        Resource,
    };

    use crate::span_processor::{
        DatadogSpanProcessor, TracePropagationData, TraceRegistry, EMPTY_PROPAGATION_DATA,
    };

    #[test]
    fn test_set_resource_from_empty_dd_config() {
        let config = Config::builder().build();

        let registry = TraceRegistry::new(Arc::new(config.clone()));
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor =
            DatadogSpanProcessor::new(Arc::new(config), registry, resource.clone(), None);

        let otel_resource = Resource::builder()
            // .with_service_name("otel-service")
            .with_attribute(KeyValue::new("key1", "value1"))
            .build();

        processor.set_resource(&otel_resource);

        let dd_resource = resource.read().unwrap();
        assert_eq!(
            dd_resource.get(&Key::from_static_str("service.name")),
            Some(Value::String("unnamed-rust-service".into()))
        );
        assert_eq!(
            dd_resource.get(&Key::from_static_str("key1")),
            Some(Value::String("value1".into()))
        );
    }

    #[test]
    fn test_set_resource_from_dd_config() {
        let mut builder = Config::builder();
        builder.set_service("test-service".to_string());
        let config = builder.build();

        let registry = TraceRegistry::new(Arc::new(config.clone()));
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor =
            DatadogSpanProcessor::new(Arc::new(config), registry, resource.clone(), None);

        let attributes = [KeyValue::new("key_schema", "value_schema")];

        let otel_resource = Resource::builder_empty()
            //.with_service_name("otel-service")
            .with_attribute(KeyValue::new("key1", "value1"))
            .with_schema_url(attributes, "schema_url")
            .build();

        processor.set_resource(&otel_resource);

        let dd_resource = resource.read().unwrap();
        assert_eq!(
            dd_resource.get(&Key::from_static_str("service.name")),
            Some(Value::String("test-service".into()))
        );
        assert_eq!(
            dd_resource.get(&Key::from_static_str("key1")),
            Some(Value::String("value1".into()))
        );
        assert_eq!(
            dd_resource.get(&Key::from_static_str("key_schema")),
            Some(Value::String("value_schema".into()))
        );

        assert_eq!(dd_resource.schema_url(), Some("schema_url"));
    }

    #[test]
    fn test_set_resource_empty_builder_from_dd_config() {
        let mut builder = Config::builder();
        builder.set_service("test-service".to_string());
        let config = builder.build();

        let registry = TraceRegistry::new(Arc::new(config.clone()));
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor =
            DatadogSpanProcessor::new(Arc::new(config), registry, resource.clone(), None);

        let otel_resource = Resource::builder_empty()
            .with_attribute(KeyValue::new("key1", "value1"))
            .build();

        processor.set_resource(&otel_resource);

        let dd_resource = resource.read().unwrap();
        assert_eq!(
            dd_resource.get(&Key::from_static_str("service.name")),
            Some(Value::String("test-service".into()))
        );
        assert_eq!(
            dd_resource.get(&Key::from_static_str("key1")),
            Some(Value::String("value1".into()))
        );
    }

    #[test]
    fn test_dd_config_non_default_service() {
        let mut builder = Config::builder();
        builder.set_service("test-service".to_string());
        let config = builder.build();

        let registry = TraceRegistry::new(Arc::new(config.clone()));
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor =
            DatadogSpanProcessor::new(Arc::new(config), registry, resource.clone(), None);

        let otel_resource = Resource::builder()
            .with_service_name("otel-service")
            .build();

        processor.set_resource(&otel_resource);

        let dd_resource = resource.read().unwrap();
        assert_eq!(
            dd_resource.get(&Key::from_static_str("service.name")),
            Some(Value::String("test-service".into()))
        );
    }

    #[test]
    fn test_dd_config_default_service() {
        let config = Config::builder().build();

        let registry = TraceRegistry::new(Arc::new(config.clone()));
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor =
            DatadogSpanProcessor::new(Arc::new(config), registry, resource.clone(), None);

        let otel_resource = Resource::builder()
            .with_service_name("otel-service")
            .build();

        processor.set_resource(&otel_resource);

        let dd_resource = resource.read().unwrap();
        assert_eq!(
            dd_resource.get(&Key::from_static_str("service.name")),
            Some(Value::String("otel-service".into()))
        );
    }

    fn bench_trace_registry(c: &mut criterion::Criterion) {
        const ITERATIONS: u32 = 10000;
        const NUM_TRACES: usize = ITERATIONS as usize / 20;
        let mut group = c.benchmark_group("trace_registry_concurrent_access_threads");
        group
            .warm_up_time(Duration::from_millis(100))
            .measurement_time(Duration::from_millis(1000));

        for concurrency in [1, 2, 4, 8, 16, 32] {
            group
                .throughput(criterion::Throughput::Elements(
                    ITERATIONS as u64 * concurrency,
                ))
                .bench_function(
                    criterion::BenchmarkId::from_parameter(concurrency),
                    move |g| {
                        let trace_ids: Vec<_> = (0..concurrency)
                            .map(|thread| {
                                std::array::from_fn::<_, NUM_TRACES, _>(|i| {
                                    ((thread << 16 | i as u64) as u128).to_be_bytes()
                                })
                            })
                            .collect();
                        g.iter_batched_ref(
                            {
                                let trace_ids = trace_ids.clone();
                                move || {
                                    let tr: TraceRegistry =
                                        TraceRegistry::new(Arc::new(Config::builder().build()));
                                    for trace_id in trace_ids.iter().flatten() {
                                        tr.register_local_root_trace_propagation_data(
                                            *trace_id,
                                            TracePropagationData {
                                                sampling_decision: SamplingDecision {
                                                    priority: Some(priority::AUTO_KEEP),
                                                    mechanism: Some(mechanism::DEFAULT),
                                                },
                                                origin: Some("rum".to_string()),
                                                tags: Some(HashMap::from_iter([(
                                                    "dd.p.tid".to_string(),
                                                    "foobar".to_string(),
                                                )])),
                                            },
                                        );
                                    }
                                    tr
                                }
                            },
                            move |tr| {
                                let tr = &*tr;
                                let trace_ids = &trace_ids;
                                thread::scope(move |s| {
                                    for trace_id in trace_ids {
                                        s.spawn(move || {
                                            for _ in 0..(ITERATIONS as usize / NUM_TRACES) {
                                                for trace_id in trace_id {
                                                    black_box(tr.get_trace_propagation_data(
                                                        black_box(*trace_id),
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                })
                            },
                            criterion::BatchSize::LargeInput,
                        );
                    },
                );
        }
    }

    #[test]
    fn bench() {
        // Run with
        // `cargo test --profile bench -- --nocapture bench -- <benchmark_filter>
        // Collect cli arguments

        // Interpret sequence of args `[ "...bench", "--", "[filter]" ]` as a trigger and extract
        // `filter`
        let filter = std::env::args()
            .collect::<Vec<_>>()
            .windows(3)
            .filter(|p| p.len() >= 2 && p[0].ends_with("bench") && p[1] == "--")
            .map(|s| s.get(2).unwrap_or(&"".to_string()).clone())
            .next();

        let filter = match filter {
            None => return,
            Some(f) => f,
        };

        let mut criterion = criterion::Criterion::default()
            .with_output_color(true)
            .with_filter(&filter);
        bench_trace_registry(&mut criterion);

        criterion.final_summary();
    }

    fn create_test_span_data(trace_id: [u8; 16], span_id: [u8; 8]) -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                TraceId::from_bytes(trace_id),
                SpanId::from_bytes(span_id),
                TraceFlags::default(),
                false,
                Default::default(),
            ),
            parent_span_id: SpanId::INVALID,
            span_kind: opentelemetry::trace::SpanKind::Internal,
            name: Cow::Borrowed("test_span"),
            start_time: std::time::SystemTime::now(),
            end_time: std::time::SystemTime::now(),
            attributes: Vec::new(),
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: opentelemetry::trace::Status::Unset,
            instrumentation_scope: Default::default(),
            parent_span_is_remote: false,
        }
    }

    #[test]
    fn test_stats_single_span_trace() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [1u8; 16];
        let span_id = [1u8; 8];

        // Register and finish a single span
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, span_id);

        let span_data = create_test_span_data(trace_id, span_id);
        registry.finish_span(trace_id, span_data);

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 1);
        assert_eq!(stats.spans_finished, 1);
        assert_eq!(stats.trace_segments_created, 1);
        assert_eq!(stats.trace_segments_closed, 1);
    }

    #[test]
    fn test_stats_multiple_spans_single_trace() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [2u8; 16];
        let root_span_id = [1u8; 8];
        let child1_span_id = [2u8; 8];
        let child2_span_id = [3u8; 8];

        // Register root span
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);

        // Register child spans
        registry.register_span(trace_id, child1_span_id, EMPTY_PROPAGATION_DATA);
        registry.register_span(trace_id, child2_span_id, EMPTY_PROPAGATION_DATA);

        // Finish all spans
        let root_span = create_test_span_data(trace_id, root_span_id);
        let child1_span = create_test_span_data(trace_id, child1_span_id);
        let child2_span = create_test_span_data(trace_id, child2_span_id);

        assert!(
            registry.finish_span(trace_id, child1_span).is_none(),
            "Should not flush incomplete trace"
        );
        assert!(
            registry.finish_span(trace_id, child2_span).is_none(),
            "Should not flush incomplete trace"
        );
        assert!(
            registry.finish_span(trace_id, root_span).is_some(),
            "Should flush complete trace"
        );

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 3);
        assert_eq!(stats.spans_finished, 3);
        assert_eq!(stats.trace_segments_created, 1);
        assert_eq!(stats.trace_segments_closed, 1);
    }

    #[test]
    fn test_stats_multiple_independent_traces() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));

        // Create 3 independent traces
        for i in 1..=3 {
            let trace_id = [i; 16];
            let span_id = [i; 8];

            registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
            registry.register_local_root_span(trace_id, span_id);

            let span_data = create_test_span_data(trace_id, span_id);
            registry.finish_span(trace_id, span_data);
        }

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 3, "Expected 3 spans created");
        assert_eq!(stats.spans_finished, 3, "Expected 3 spans finished");
        assert_eq!(
            stats.trace_segments_created, 3,
            "Expected 3 trace segments created"
        );
        assert_eq!(
            stats.trace_segments_closed, 3,
            "Expected 3 trace segments closed"
        );
    }

    #[test]
    fn test_stats_unfinished_trace() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [4u8; 16];
        let root_span_id = [1u8; 8];
        let child_span_id = [2u8; 8];

        // Register root and child spans
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);
        registry.register_span(trace_id, child_span_id, EMPTY_PROPAGATION_DATA);

        // Only finish the root span
        let root_span = create_test_span_data(trace_id, root_span_id);
        assert!(
            registry.finish_span(trace_id, root_span).is_none(),
            "Should not flush incomplete trace"
        );

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 2);
        assert_eq!(stats.spans_finished, 1);
        assert_eq!(stats.trace_segments_created, 1);
        assert_eq!(stats.trace_segments_closed, 0);
    }

    #[test]
    fn test_stats_orphaned_span() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [5u8; 16];
        let span_id = [1u8; 8];

        // Finish a span without registering it first
        let span_data = create_test_span_data(trace_id, span_id);
        assert!(
            registry.finish_span(trace_id, span_data).is_some(),
            "Should flush orphaned span immediately"
        );

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 0);
        assert_eq!(stats.spans_finished, 1);
        assert_eq!(stats.trace_segments_created, 1);
        assert_eq!(stats.trace_segments_closed, 1);
    }

    #[test]
    fn test_stats_reset_after_get() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [6u8; 16];
        let span_id = [1u8; 8];

        // Create and finish a trace
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, span_id);
        let span_data = create_test_span_data(trace_id, span_id);
        registry.finish_span(trace_id, span_data);

        // Get stats (should reset them)
        let stats1 = registry.get_metrics();
        assert_eq!(stats1.spans_created, 1);

        // Get stats again (should be zero)
        let stats2 = registry.get_metrics();
        assert_eq!(stats2.spans_created, 0);
        assert_eq!(stats2.spans_finished, 0);
        assert_eq!(stats2.trace_segments_created, 0);
        assert_eq!(stats2.trace_segments_closed, 0);
    }

    #[test]
    fn test_stats_across_multiple_shards() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));

        // Create traces that will likely hit different shards
        let num_traces = 100;
        for i in 0..num_traces {
            let trace_id = (i as u128).to_be_bytes();
            let span_id = [i as u8; 8];

            registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
            registry.register_local_root_span(trace_id, span_id);

            let span_data = create_test_span_data(trace_id, span_id);
            registry.finish_span(trace_id, span_data);
        }

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, num_traces);
        assert_eq!(stats.spans_finished, num_traces);
        assert_eq!(stats.trace_segments_created, num_traces);
        assert_eq!(stats.trace_segments_closed, num_traces);
    }

    #[test]
    fn test_stats_complex_trace_hierarchy() {
        let registry = TraceRegistry::new(Arc::new(Config::builder().build()));
        let trace_id = [7u8; 16];
        let root_span_id = [1u8; 8];

        // Register root
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);

        // Register 5 child spans
        for i in 2..=6 {
            let child_span_id = [i; 8];
            registry.register_span(trace_id, child_span_id, EMPTY_PROPAGATION_DATA);
        }

        // Finish all spans
        for i in 1..=6 {
            let span_id = [i; 8];
            let span_data = create_test_span_data(trace_id, span_id);
            let result = registry.finish_span(trace_id, span_data);
            if i == 6 {
                assert!(result.is_some(), "Should flush after last span");
            } else {
                assert!(
                    result.is_none(),
                    "Should not flush before all spans complete"
                );
            }
        }

        let stats = registry.get_metrics();
        assert_eq!(stats.spans_created, 6);
        assert_eq!(stats.spans_finished, 6);
        assert_eq!(stats.trace_segments_created, 1)
    }

    #[test]
    fn test_partial_flush_disabled_by_default() {
        let config = Config::builder().build();
        let registry = TraceRegistry::new(Arc::new(config));
        let trace_id = [8u8; 16];
        let root_span_id = [1u8; 8];

        // Register root span
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);

        // Register and finish more than default min_spans
        for i in 2..=400 {
            let child_span_id = [0, 0, 0, 0, 0, 0, (i / 256) as u8, i as u8];
            registry.register_span(trace_id, child_span_id, EMPTY_PROPAGATION_DATA);
            let span_data = create_test_span_data(trace_id, child_span_id);

            // With partial flushing disabled, no trace should be flushed until all spans are done
            let result = registry.finish_span(trace_id, span_data);
            assert!(
                result.is_none(),
                "Should not flush until all spans are done (disabled by default)"
            );
        }

        // Finish root span - now it should flush
        let root_span = create_test_span_data(trace_id, root_span_id);
        let result = registry.finish_span(trace_id, root_span);
        assert!(result.is_some(), "Should flush after all spans are done");
        let trace = result.unwrap();
        assert_eq!(trace.finished_spans.len(), 400);
        let metrics = registry.get_metrics();
        assert_eq!(metrics.trace_partial_flush_count, 0);
        assert_eq!(metrics.trace_segments_closed, 1);
    }

    #[test]
    fn test_partial_flush_enabled_min_spans() {
        let config = Config::builder()
            .set_trace_partial_flush_enabled(true)
            .set_trace_partial_flush_min_spans(10)
            .build();
        let registry = TraceRegistry::new(Arc::new(config));
        let trace_id = [9u8; 16];
        let root_span_id = [1u8; 8];

        // Register root span
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);

        // Register 15 child spans
        for i in 2..=16 {
            let child_span_id = [i; 8];
            registry.register_span(trace_id, child_span_id, EMPTY_PROPAGATION_DATA);
        }

        // Finish 9 spans (below threshold)
        for i in 2..=10 {
            let span_data = create_test_span_data(trace_id, [i; 8]);
            let result = registry.finish_span(trace_id, span_data);
            assert!(
                result.is_none(),
                "Should not flush until min_spans threshold is reached"
            );
        }

        // Finish the 10th span (reaches threshold)
        let span_data = create_test_span_data(trace_id, [11; 8]);
        let result = registry.finish_span(trace_id, span_data);
        assert!(
            result.is_some(),
            "Should flush when min_spans threshold is reached"
        );
        let trace = result.unwrap();
        let metrics = registry.get_metrics();
        assert_eq!(metrics.trace_partial_flush_count, 1);
        assert_eq!(metrics.trace_segments_closed, 0);

        assert_eq!(trace.finished_spans.len(), 10);
        assert_eq!(
            trace.open_span_count, 6,
            "Should have 6 open spans remaining (root + 5 children)"
        );
    }

    #[test]
    fn test_partial_flush_multiple_flushes() {
        let config = Config::builder()
            .set_trace_partial_flush_enabled(true)
            .set_trace_partial_flush_min_spans(5)
            .build();
        let registry = TraceRegistry::new(Arc::new(config));
        let trace_id = [10u8; 16];
        let root_span_id = [1u8; 8];

        // Register root span
        registry.register_local_root_trace_propagation_data(trace_id, EMPTY_PROPAGATION_DATA);
        registry.register_local_root_span(trace_id, root_span_id);

        // Register 20 child spans
        for i in 2..=21 {
            let child_span_id = [i; 8];
            registry.register_span(trace_id, child_span_id, EMPTY_PROPAGATION_DATA);
        }

        let mut total_flushed = 0;
        let mut flush_count = 0;

        // Finish all child spans
        for i in 2..=21 {
            let span_data = create_test_span_data(trace_id, [i; 8]);
            if let Some(trace) = registry.finish_span(trace_id, span_data) {
                total_flushed += trace.finished_spans.len();
                flush_count += 1;
            }
        }

        // Should have multiple partial flushes
        assert_eq!(flush_count, 4, "Should have 4 partial flushes");
        assert_eq!(total_flushed, 20, "Should have flushed all 20 child spans");
        let metrics = registry.get_metrics();
        assert_eq!(metrics.trace_partial_flush_count, 4);
        assert_eq!(metrics.trace_segments_closed, 0);

        // Finish root span - final flush
        let root_span = create_test_span_data(trace_id, root_span_id);
        let result = registry.finish_span(trace_id, root_span);
        assert!(result.is_some(), "Should flush root span");
        let trace = result.unwrap();
        assert_eq!(trace.finished_spans.len(), 1);
        assert_eq!(trace.open_span_count, 0);
        let metrics = registry.get_metrics();
        assert_eq!(
            metrics.trace_partial_flush_count, 0,
            "Last flush is a complete one"
        );
        assert_eq!(metrics.trace_segments_closed, 1);
    }
}
