// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use hashbrown::{hash_map, HashMap as BHashMap};
use std::{
    collections::HashMap,
    fmt::Debug,
    str::FromStr,
    sync::{Arc, RwLock},
};

use dd_trace::{
    configuration::remote_config::{
        RemoteConfigClientError, RemoteConfigClientHandle, RemoteConfigClientWorker,
    },
    constants::SAMPLING_DECISION_MAKER_TAG_KEY,
    sampling::SamplingDecision,
    telemetry::init_telemetry,
};
use opentelemetry::{
    global::ObjectSafeSpan,
    trace::{SpanContext, TraceContextExt, TraceState},
    Key, KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::trace::SpanData;
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

use crate::{
    create_dd_resource, span_exporter::DatadogExporter, text_map_propagator::DatadogExtractData,
};

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
}

pub enum RegisterTracePropagationResult {
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
            dd_trace::dd_debug!(
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
            .or_insert_with(|| Trace {
                local_root_span_id: span_id,
                finished_spans: Vec::new(),
                open_span_count: 0,
                propagation_data,
            })
            .open_span_count += 1;
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
    /// Currently traces with unfinished spans are kept forever in memory.
    /// This lead to unbounded memory usage, if new spans keep getting added to the trace.
    /// TODO: We should implement partial flushing, as this will allow use to flush traces that are
    /// too big, and avoid unbounded memory usage.
    fn finish_span(&mut self, trace_id: [u8; 16], span_data: SpanData) -> Option<Trace> {
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
            if trace.open_span_count == 0 {
                Some(slot.remove())
            } else {
                None
            }
        } else {
            // if we somehow don't have the trace registered, we just flush the span...

            dd_trace::dd_debug!(
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
pub(crate) struct TraceRegistry {
    // Example:
    // inner: Arc<[CacheAligned<RwLock<InnerTraceRegistry>>; N]>;
    // to access a trace we do inner[hash(trace_id) % N].read()
    inner: Arc<[CachePadded<RwLock<InnerTraceRegistry>>; TRACE_REGISTRY_SHARDS]>,
    hasher: foldhash::fast::RandomState,
}

impl TraceRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(std::array::from_fn(|_| {
                CachePadded(RwLock::new(InnerTraceRegistry {
                    registry: BHashMap::new(),
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

    pub fn get_trace_propagation_data(&self, trace_id: [u8; 16]) -> TracePropagationData {
        let inner = self
            .get_shard(trace_id)
            .read()
            .expect("Failed to acquire lock on trace registry");

        inner.get_trace_propagation_data(trace_id).clone()
    }
}

pub(crate) struct DatadogSpanProcessor {
    registry: TraceRegistry,
    span_exporter: DatadogExporter,
    resource: Arc<RwLock<Resource>>,
    config: Arc<dd_trace::Config>,
    rc_client_handle: Option<RemoteConfigClientHandle>,
}

impl std::fmt::Debug for DatadogSpanProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogSpanProcessor").finish()
    }
}

impl DatadogSpanProcessor {
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        config: Arc<dd_trace::Config>,
        registry: TraceRegistry,
        resource: Arc<RwLock<Resource>>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    ) -> Self {
        let rc_client_handle = if config.remote_config_enabled() {
            RemoteConfigClientWorker::start(config.clone())
                .inspect_err(|e| {
                    dd_trace::dd_error!(
                        "RemoteConfigClientWorker.start: Failed to start remote config client: {}",
                        e
                    );
                })
                .ok()
        } else {
            None
        };
        // Create remote config client with shared config

        // Extract config clone before moving the Arc
        let config_clone = config.clone();
        Self {
            registry,
            span_exporter: DatadogExporter::new(
                config_clone.as_ref().clone(),
                agent_response_handler,
            ),
            resource,
            config,
            rc_client_handle,
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

        let Some(trace) = self.registry.finish_span(trace_id, span) else {
            return;
        };

        // Add propagation data before exporting the trace
        let trace_chunk = self.add_trace_propagation_data(trace);
        if let Err(e) = self.span_exporter.export_chunk_no_wait(trace_chunk) {
            dd_trace::dd_error!(
                "DatadogSpanProcessor.on_end message='Failed to export trace chunk' error='{e}'",
            );
        }
    }

    fn force_flush(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.span_exporter.force_flush()
    }

    fn shutdown_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> opentelemetry_sdk::error::OTelSdkResult {
        let deadline = std::time::Instant::now() + timeout;
        self.span_exporter.trigger_shutdown();
        if let Some(rc_client_handle) = &self.rc_client_handle {
            rc_client_handle.trigger_shutdown();
        };
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        self.span_exporter
            .wait_for_shutdown(left)
            .map_err(|e| match e {
                opentelemetry_sdk::error::OTelSdkError::Timeout(_) => {
                    opentelemetry_sdk::error::OTelSdkError::Timeout(timeout)
                }
                _ => e,
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
        Ok(())
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        let dd_resource = create_dd_resource(resource.clone(), &self.config);
        if let Err(e) = self.span_exporter.set_resource(dd_resource.clone()) {
            dd_trace::dd_error!(
                "DatadogSpanProcessor.set_resource message='Failed to set resource' error='{e}'",
            );
        }
        // set the shared resource in the DatadogSpanProcessor
        *self.resource.write().unwrap() = dd_resource.clone();

        // update config's service name and init telemetry once service name has been resolved
        let service_name = dd_resource
            .get(&Key::from_static_str(SERVICE_NAME))
            .map(|service_name| service_name.as_str().to_string());
        self.config.update_service_name(service_name);

        init_telemetry(&self.config);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        hint::black_box,
        sync::{Arc, RwLock},
        thread,
        time::Duration,
    };

    use dd_trace::{
        sampling::{mechanism, priority, SamplingDecision},
        Config,
    };
    use opentelemetry::{Key, KeyValue, Value};
    use opentelemetry_sdk::{trace::SpanProcessor, Resource};

    use crate::span_processor::{DatadogSpanProcessor, TracePropagationData, TraceRegistry};

    #[test]
    fn test_set_resource_from_empty_dd_config() {
        let config = Config::builder().build();

        let registry = TraceRegistry::new();
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

        let registry = TraceRegistry::new();
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

        let registry = TraceRegistry::new();
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

        let registry = TraceRegistry::new();
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

        let registry = TraceRegistry::new();
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
                                    let tr: TraceRegistry = TraceRegistry::new();
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

        // Interpret sequence of args `[ "...bench", "--", "[filter]" ]` as a trigger and extract `filter`
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
}
