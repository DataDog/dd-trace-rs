// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to dd-trace

use std::{borrow::Cow, collections::hash_map, time::SystemTime};

use datadog_trace_utils::span::SpanBytes as DdSpan;
use dd_trace::constants::{SAMPLING_DECISION_AUTO_DROP, SAMPLING_DECISION_AUTO_KEEP};
use opentelemetry::trace::Event;
use opentelemetry_sdk::{trace::SpanData, Resource};
use tinybytes::BytesString;

use crate::transform;

/// Intermediary struct that we can create and use to write tests
/// on the span conversion
pub(crate) struct ExportSpan {
    pub span_context: opentelemetry::trace::SpanContext,
    pub parent_span_id: opentelemetry::trace::SpanId,
    pub span_kind: opentelemetry::trace::SpanKind,
    pub name: Cow<'static, str>,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub attributes: Vec<opentelemetry::KeyValue>,
    #[allow(dead_code)]
    pub dropped_attributes_count: u32,
    pub events: Vec<Event>,
    #[allow(dead_code)]
    pub dropped_event_count: u32,
    pub links: Vec<opentelemetry::trace::Link>,
    #[allow(dead_code)]
    pub dropped_links_count: u32,
    pub status: opentelemetry::trace::Status,
    pub instrumentation_scope: opentelemetry::InstrumentationScope,
}

impl ExportSpan {
    pub(crate) fn from_otel_span(span: SpanData) -> Self {
        ExportSpan {
            span_context: span.span_context,
            parent_span_id: span.parent_span_id,
            span_kind: span.span_kind,
            name: span.name,
            start_time: span.start_time,
            end_time: span.end_time,
            attributes: span.attributes,
            dropped_attributes_count: span.dropped_attributes_count,
            events: span.events.events,
            dropped_event_count: span.events.dropped_count,
            links: span.links.links,
            dropped_links_count: span.links.dropped_count,
            status: span.status,
            instrumentation_scope: span.instrumentation_scope,
        }
    }
}

/// The OTLP receiver in the agent only receives sampled spans
/// because others are dropped in the process. In this spirit, we check for the sampling
/// decision taken by the datadog sampler, and if it is missing assign AUTO_KEEP/AUTO_DROP
/// based on the otel sampling decision.
fn otel_sampling_to_dd_sampling(
    otel_trace_flags: opentelemetry::trace::TraceFlags,
    dd_span: &mut DdSpan,
) {
    if let hash_map::Entry::Vacant(e) = dd_span
        .metrics
        .entry(BytesString::from_static("_sampling_priority_v1"))
    {
        if otel_trace_flags.is_sampled() {
            e.insert(SAMPLING_DECISION_AUTO_KEEP as f64);
        } else {
            e.insert(SAMPLING_DECISION_AUTO_DROP as f64);
        }
    }
}

// Transform a vector of opentelemetry span data into a vector of datadog tracechunks
pub fn otel_trace_chunk_to_dd_trace_chunk(
    cfg: &dd_trace::Config,
    span_data: Vec<SpanData>,
    otel_resource: &Resource,
) -> Vec<DdSpan> {
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    span_data
        .into_iter()
        .map(|s| {
            let trace_flags = s.span_context.trace_flags();
            let mut dd_span =
                transform::otel_span_to_dd_span(ExportSpan::from_otel_span(s), otel_resource);
            otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);
            if dd_span.service == transform::DEFAULT_OTLP_SERVICE_NAME {
                dd_span.service = BytesString::from_string(cfg.service().to_string());
            }

            dd_span
        })
        .collect()
}
