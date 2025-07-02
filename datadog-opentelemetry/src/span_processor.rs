// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{hash_map, HashMap},
    str::FromStr,
    sync::{Arc, RwLock},
};

use dd_trace::{constants::SAMPLING_DECISION_MAKER_TAG_KEY, sampling::SamplingDecision};
use opentelemetry::{
    global::ObjectSafeSpan,
    trace::{SpanContext, TraceContextExt, TraceState},
    KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::trace::SpanData;
use opentelemetry_sdk::Resource;

use crate::{span_exporter::DatadogExporter, text_map_propagator::DatadogExtractData};

#[derive(Debug)]
struct Trace {
    root_span_id: [u8; 8],
    /// Root span will always be the first span in this vector if it is present
    finished_spans: Vec<SpanData>,
    open_span_count: usize,

    sampling_decision: Option<SamplingDecision>,
    origin: Option<String>,
    tags: Option<HashMap<String, String>>,
}

pub(crate) struct TracePropagationData {
    pub sampling_decision: Option<SamplingDecision>,
    pub origin: Option<String>,
    pub tags: Option<HashMap<String, String>>,
}

const EMPTY_PROPAGATION_DATA: TracePropagationData = TracePropagationData {
    origin: None,
    sampling_decision: None,
    tags: None,
};

#[derive(Debug)]
struct InnerTraceRegistry {
    registry: HashMap<[u8; 16], Trace>,
}

pub enum RegisterTracePropagationResult {
    Existing(SamplingDecision),
    New,
}

impl InnerTraceRegistry {
    fn register_trace_propagation_data(
        &mut self,
        trace_id: [u8; 16],
        sampling_decision: SamplingDecision,
        origin: Option<String>,
        tags: Option<HashMap<String, String>>,
    ) -> RegisterTracePropagationResult {
        match self.registry.entry(trace_id) {
            hash_map::Entry::Occupied(mut occupied_entry) => {
                if let Some(existing_sampling_decision) = occupied_entry.get().sampling_decision {
                    RegisterTracePropagationResult::Existing(existing_sampling_decision)
                } else {
                    let trace = occupied_entry.get_mut();
                    trace.sampling_decision = Some(sampling_decision);
                    trace.origin = origin;
                    trace.tags = tags;
                    RegisterTracePropagationResult::New
                }
            }
            hash_map::Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(Trace {
                    root_span_id: [0; 8], // This will be set when the first span is registered
                    finished_spans: Vec::new(),
                    open_span_count: 0,
                    sampling_decision: Some(sampling_decision),
                    origin,
                    tags,
                });
                RegisterTracePropagationResult::New
            }
        }
    }

    fn register_root_span(&mut self, trace_id: [u8; 16], root_span_id: [u8; 8]) {
        let trace = self.registry.entry(trace_id).or_insert_with(|| Trace {
            root_span_id: [0; 8], // This will be set when the first span is registered
            finished_spans: Vec::new(),
            open_span_count: 0,
            sampling_decision: None,
            origin: None,
            tags: None,
        });
        if trace.root_span_id == [0; 8] {
            trace.root_span_id = root_span_id;
            trace.open_span_count = 1;
        } else {
            dd_trace::dd_debug!(
                "trace with trace_id={:?} already has a root span registered with root_span_id={:?}. Ignoring the new root_span_id={:?}",
                trace_id,
                trace.root_span_id,
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
        TracePropagationData {
            origin,
            sampling_decision,
            tags,
        }: TracePropagationData,
    ) {
        self.registry
            .entry(trace_id)
            .or_insert_with(|| Trace {
                root_span_id: span_id,
                finished_spans: Vec::new(),
                open_span_count: 0,
                sampling_decision,
                origin,
                tags,
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
            if !trace.finished_spans.is_empty()
                && span_data.span_context.span_id().to_bytes() == trace.root_span_id
            {
                let swapped_span = std::mem::replace(&mut trace.finished_spans[0], span_data);
                trace.finished_spans.push(swapped_span);
            } else {
                trace.finished_spans.push(span_data);
            }
            trace.open_span_count -= 1;
            if trace.open_span_count == 0 {
                Some(slot.remove())
            } else {
                None
            }
        } else {
            // if we somehow don't have the trace registered, we just flush the span...
            // this is probably a bug, so we should log telemetry
            Some(Trace {
                root_span_id: span_data.span_context.span_id().to_bytes(),
                finished_spans: vec![span_data],
                open_span_count: 0,
                sampling_decision: None,
                origin: None,
                tags: None,
            })
        }
    }

    fn get_trace_propagation_data(&self, trace_id: [u8; 16]) -> TracePropagationData {
        match self.registry.get(&trace_id) {
            Some(trace) => TracePropagationData {
                sampling_decision: trace.sampling_decision,
                origin: trace.origin.clone(),
                tags: trace.tags.clone(),
            },
            None => TracePropagationData {
                sampling_decision: None,
                origin: None,
                tags: None,
            },
        }
    }
}

#[derive(Clone, Debug)]
/// A registry of traces that are currently running
///
/// This registry maintains the following information:
/// - The root span ID of the trace
/// - The finished spans of the trace
/// - The number of open spans in the trace
/// - The sampling decision of the trace
pub(crate) struct TraceRegistry {
    // TODO: The lock should probably sharded based on the hash of the trace id
    // so we reduce contention...
    // Example:
    // inner: Arc<[CacheAligned<RwLock<InnerTraceRegistry>>; N]>;
    // to access a trace we do inner[hash(trace_id) % N].read()
    inner: Arc<RwLock<InnerTraceRegistry>>,
}

impl TraceRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(InnerTraceRegistry {
                registry: HashMap::new(),
            })),
        }
    }

    /// Register trace propagation data for a given trace ID.
    /// This does not set the root span ID or increment the open span count.
    ///
    /// If the trace is already registered with a non None sampling decision,
    /// it will return the existing sampling decision instead
    pub fn register_trace_propagation_data(
        &self,
        trace_id: [u8; 16],
        sampling_decision: SamplingDecision,
        origin: Option<String>,
        tags: Option<HashMap<String, String>>,
    ) -> RegisterTracePropagationResult {
        let mut inner = self
            .inner
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_trace_propagation_data(trace_id, sampling_decision, origin, tags)
    }

    /// Set the root span ID for a given trace ID.
    /// This will also increment the open span count for the trace.
    /// If the trace is already registered, it will ignore the new root span ID and log a warning.
    pub fn register_root_span(&self, trace_id: [u8; 16], root_span_id: [u8; 8]) {
        let mut inner = self
            .inner
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_root_span(trace_id, root_span_id);
    }

    /// Register a new span with the given trace ID and span ID.
    pub fn register_span(
        &self,
        trace_id: [u8; 16],
        span_id: [u8; 8],
        propagation_data: TracePropagationData,
    ) {
        let mut inner = self
            .inner
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.register_span(trace_id, span_id, propagation_data);
    }

    /// Finish a span with the given trace ID and span data.
    /// If the trace is finished (i.e., all spans are finished), return the full trace chunk to
    /// flush
    fn finish_span(&self, trace_id: [u8; 16], span_data: SpanData) -> Option<Trace> {
        let mut inner = self
            .inner
            .write()
            .expect("Failed to acquire lock on trace registry");
        inner.finish_span(trace_id, span_data)
    }

    pub fn get_trace_propagation_data(&self, trace_id: [u8; 16]) -> TracePropagationData {
        let inner = self
            .inner
            .read()
            .expect("Failed to acquire lock on trace registry");

        inner.get_trace_propagation_data(trace_id)
    }
}

pub(crate) struct DatadogSpanProcessor {
    config_service_name: String,
    registry: Arc<TraceRegistry>,
    span_exporter: DatadogExporter,
    resource: Arc<RwLock<Resource>>,
}

impl std::fmt::Debug for DatadogSpanProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogSpanProcessor").finish()
    }
}

impl DatadogSpanProcessor {
    pub(crate) fn new(
        config: dd_trace::Config,
        registry: Arc<TraceRegistry>,
        resource: Arc<RwLock<Resource>>,
    ) -> Self {
        let config_service_name = config.service().to_string();
        Self {
            config_service_name,
            registry,
            span_exporter: DatadogExporter::new(config),
            resource,
        }
    }

    /// If SpanContext is remote, recover [`DatadogExtractData`] from parent context:
    /// - links generated during extraction are added to the root span as span links.
    /// - sampling decision, origin and tags are returned to be stored as Trace propagation data
    fn get_remote_propagation_data(
        &self,
        span: &mut opentelemetry_sdk::trace::Span,
        parent_ctx: &opentelemetry::Context,
    ) -> TracePropagationData {
        if let Some(DatadogExtractData {
            links,
            internal_tags,
            origin,
            sampling,
        }) = parent_ctx.get::<DatadogExtractData>().cloned()
        {
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

            let sampling_decision = sampling.and_then(|sampling| {
                Some(SamplingDecision {
                    priority: sampling.priority?,
                    mechanism: sampling.mechanism.unwrap_or_default(),
                })
            });
            return TracePropagationData {
                origin,
                sampling_decision,
                tags: Some(internal_tags),
            };
        }

        EMPTY_PROPAGATION_DATA
    }

    /// If [`Trace`] contains origin, tags or sampling_decision add them as attributes of the root
    /// span
    fn add_trace_propagation_data(&self, mut trace: Trace) -> Vec<SpanData> {
        let origin = trace.origin.unwrap_or_default();

        for span in trace.finished_spans.iter_mut() {
            if span.span_context.span_id().to_bytes() == trace.root_span_id {
                if let Some(ref tags) = trace.tags {
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
            // they shouldn't be overrided
            if let Some(sampling_decision) = trace.sampling_decision {
                span.attributes.push(KeyValue::new(
                    "_sampling_priority_v1",
                    sampling_decision.priority.into_i8() as i64,
                ));

                span.attributes.push(KeyValue::new(
                    SAMPLING_DECISION_MAKER_TAG_KEY,
                    sampling_decision.mechanism.to_cow(),
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
        if !span.is_recording() || !span.span_context().is_valid() {
            return;
        }

        let trace_id = span.span_context().trace_id().to_bytes();
        let span_id = span.span_context().span_id().to_bytes();

        if parent_ctx.span().span_context().is_remote() {
            let propagation_data = self.get_remote_propagation_data(span, parent_ctx);
            self.registry
                .register_span(trace_id, span_id, propagation_data);
        } else if !parent_ctx.has_active_span() {
            self.registry.register_root_span(trace_id, span_id);
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

    fn shutdown(&self) -> opentelemetry_sdk::error::OTelSdkResult {
        self.span_exporter.shutdown()
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        let dd_resource = if !self.config_service_name.is_empty() {
            let mut builder = opentelemetry_sdk::Resource::builder_empty();
            if let Some(schema_url) = resource.schema_url() {
                builder = builder.with_schema_url(
                    resource
                        .iter()
                        .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
                    schema_url.to_string(),
                );
            } else {
                builder = builder.with_attributes(
                    resource
                        .iter()
                        .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
                );
            }

            builder
                .with_service_name(self.config_service_name.clone())
                .build()
        } else {
            resource.clone()
        };

        if let Err(e) = self.span_exporter.set_resource(dd_resource.clone()) {
            dd_trace::dd_error!(
                "DatadogSpanProcessor.set_resource message='Failed to set resource' error='{e}'",
            );
        }
        // set the shared resource in the DatadogSpanProcessor
        *self.resource.write().unwrap() = dd_resource;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use dd_trace::Config;
    use opentelemetry::{Key, KeyValue, Value};
    use opentelemetry_sdk::{trace::SpanProcessor, Resource};

    use crate::span_processor::{DatadogSpanProcessor, TraceRegistry};

    #[test]
    fn test_set_resource_from_empty_dd_config() {
        let builder = Config::builder();
        let config = builder.build();

        let registry = Arc::new(TraceRegistry::new());
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor = DatadogSpanProcessor::new(config, registry, resource.clone());

        let otel_resource = Resource::builder()
            .with_service_name("otel-service")
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

        let registry = Arc::new(TraceRegistry::new());
        let resource = Arc::new(RwLock::new(Resource::builder_empty().build()));

        let mut processor = DatadogSpanProcessor::new(config, registry, resource.clone());

        let attributes = [KeyValue::new("key_schema", "value_schema")];

        let otel_resource = Resource::builder()
            .with_service_name("otel-service")
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
}
