// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to dd-trace

use std::collections::{hash_map, HashMap};

use datadog_trace_utils::span::SpanBytes as DdSpan;
use dd_trace::constants::{SAMPLING_DECISION_AUTO_DROP, SAMPLING_DECISION_AUTO_KEEP};
use opentelemetry_sdk::{trace::SpanData, Resource};
use tinybytes::BytesString;

use crate::transform;

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
pub fn otel_span_data_to_dd_trace_chunks(
    cfg: &dd_trace::Config,
    span_data: Vec<SpanData>,
    otel_ressource: &Resource,
) -> Vec<Vec<DdSpan>> {
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    span_data
        .into_iter()
        .map(|s| {
            let trace_id = s.span_context.trace_id();
            let trace_flags = s.span_context.trace_flags();
            let mut dd_span = transform::otel_span_to_dd_span(s, otel_ressource);
            otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);
            if dd_span.service == transform::DEFAULT_OTLP_SERVICE_NAME {
                dd_span.service = BytesString::from_string(cfg.service().to_string());
            }

            (trace_id, dd_span)
        })
        .fold(HashMap::<_, Vec<_>>::new(), |mut acc, (trace_id, span)| {
            acc.entry(trace_id).or_default().push(span);
            acc
        })
        .into_values()
        .collect()
}
