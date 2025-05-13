// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{hash_map, HashMap},
    str::FromStr,
    sync::{Arc, RwLock},
};

use opentelemetry::{
    global::ObjectSafeSpan,
    trace::{SpanContext, TraceContextExt, TraceState},
    KeyValue, SpanId, TraceFlags, TraceId,
};
use opentelemetry_sdk::trace::SpanData;

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

#[derive(Clone, Copy, Debug)]
pub struct SamplingDecision {
    pub decision: i8,
    pub decision_maker: i8,
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

impl InnerTraceRegistry {
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
    registry: Arc<TraceRegistry>,
    span_exporter: DatadogExporter,
}

impl std::fmt::Debug for DatadogSpanProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogSpanProcessor").finish()
    }
}

impl DatadogSpanProcessor {
    pub(crate) fn new(config: dd_trace::Config, registry: Arc<TraceRegistry>) -> Self {
        Self {
            registry,
            span_exporter: DatadogExporter::new(config),
        }
    }

    fn add_links_and_get_propagation_data(
        &self,
        span: &mut opentelemetry_sdk::trace::Span,
        parent_ctx: &opentelemetry::Context,
    ) -> TracePropagationData {
        if !parent_ctx.span().span_context().is_remote() {
            return EMPTY_PROPAGATION_DATA;
        }

        if let Some(DatadogExtractData {
            links,
            propagation_tags,
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

            let sampling_decision = sampling.map(|sampling| SamplingDecision {
                decision: sampling.priority.unwrap_or_default() as i8,
                decision_maker: sampling.mechanism.unwrap_or_default() as i8,
            });
            return TracePropagationData {
                origin,
                sampling_decision,
                tags: Some(propagation_tags),
            };
        }

        EMPTY_PROPAGATION_DATA
    }

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

            // TODO: is this correct? What if _sampling_priority_v1 or _dd.p.dm were extracted? they shouldn't be overrided
            if let Some(sampling_decision) = trace.sampling_decision {
                span.attributes.push(KeyValue::new(
                    "_sampling_priority_v1",
                    sampling_decision.decision.clone() as i64,
                ));

                span.attributes.push(KeyValue::new(
                    "_dd.p.dm",
                    format!("-{}", sampling_decision.decision_maker.clone()),
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
        let trace_id = span.span_context().trace_id().to_bytes();
        let span_id = span.span_context().span_id().to_bytes();

        let propagation_data = self.add_links_and_get_propagation_data(span, parent_ctx);
        self.registry
            .register_span(trace_id, span_id, propagation_data);
    }

    fn on_end(&self, span: SpanData) {
        let trace_id = span.span_context.trace_id().to_bytes();
        let Some(trace) = self.registry.finish_span(trace_id, span) else {
            return;
        };

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
        if let Err(e) = self.span_exporter.set_resource(resource.clone()) {
            dd_trace::dd_error!(
                "DatadogSpanProcessor.set_resource message='Failed to set resource' error='{e}'",
            );
        }
    }
}
