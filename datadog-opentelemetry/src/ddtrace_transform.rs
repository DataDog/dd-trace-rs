// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to datadog-opentelemetry

use crate::{
    core::sampling,
    mappings::{
        otel_span_to_dd_span, CachedConfig, DdSpan, SdkSpan, SpanStr, DEFAULT_OTLP_SERVICE_NAME,
        VERSION_KEY,
    },
};
use libdd_trace_utils::span::SpanText;
use opentelemetry::Key;
use opentelemetry_sdk::{trace::SpanData, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

static SERVICE_NAME_KEY: Key = Key::from_static_str(SERVICE_NAME);

/// The OTLP receiver in the agent only receives sampled spans
/// because others are dropped in the process. In this spirit, we check for the sampling
/// decision taken by the datadog sampler, and if it is missing assign AUTO_KEEP/AUTO_DROP
/// based on the otel sampling decision.
fn otel_sampling_to_dd_sampling(
    otel_trace_flags: opentelemetry::trace::TraceFlags,
    dd_span: &mut DdSpan,
) {
    let priority_key = SpanStr::from_static_str("_sampling_priority_v1");
    if !dd_span.metrics.contains_key(&priority_key) {
        let priority = if otel_trace_flags.is_sampled() {
            sampling::priority::AUTO_KEEP
        } else {
            sampling::priority::AUTO_REJECT
        };
        dd_span
            .metrics
            .insert(priority_key, priority.into_i8() as f64);
    }
}

/// Whether a trace chunk was kept by the sampler (its sampling priority is positive).
///
/// Used to strictly honor the OTel sampling decision on the OTLP export path. libdatadog's send
/// path retains chunks containing an error span (and single-span-sampled spans) regardless of
/// priority — correct for the Datadog agent, but for OTLP it would leak spans the OTel sampler
/// dropped (e.g. an error span under `OTEL_TRACES_SAMPLER=parentbased_always_off`). Mirrors
/// libdatadog's priority lookup: the chunk priority is the first span's `_sampling_priority_v1`,
/// and a chunk with no priority is kept.
pub(crate) fn chunk_is_sampled(chunk: &[DdSpan]) -> bool {
    let priority_key = SpanStr::from_static_str("_sampling_priority_v1");
    chunk
        .iter()
        .find_map(|span| span.metrics.get(&priority_key))
        .is_none_or(|priority| *priority > 0.0)
}

// Transform a vector of opentelemetry span data into a vector of datadog tracechunks
pub fn otel_trace_chunk_to_dd_trace_chunk<'a>(
    cached_config: &'a CachedConfig,
    span_data: &'a [SpanData],
    otel_resource: &'a Resource,
) -> Vec<DdSpan<'a>> {
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    span_data
        .iter()
        .map(|s| {
            let trace_flags = s.span_context.trace_flags();
            let sdk_span = SdkSpan::from_sdk_span_data(s);
            let mut dd_span = otel_span_to_dd_span(&sdk_span, otel_resource);
            otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);

            add_config_metadata(&mut dd_span, cached_config, otel_resource);

            dd_span
        })
        .collect()
}

fn add_config_metadata<'a>(
    dd_span: &mut DdSpan<'a>,
    cached_config: &'a CachedConfig,
    otel_resource: &'a Resource,
) {
    dd_span.meta.insert(
        SpanStr::from_static_str("telemetry.sdk.name"),
        SpanStr::from_static_str("datadog"),
    );
    dd_span.meta.insert(
        SpanStr::from_static_str("telemetry.sdk.version"),
        SpanStr::from_str(&cached_config.tracer_version),
    );

    if dd_span.service.as_str() == DEFAULT_OTLP_SERVICE_NAME {
        dd_span.service = SpanStr::from_str(&cached_config.service);
    }

    for (key, value) in &cached_config.global_tags {
        dd_span
            .meta
            .insert(SpanStr::from_str(key), SpanStr::from_str(value));
    }

    if let Some(version) = &cached_config.version {
        if let Some(service_name) = otel_resource.get(&SERVICE_NAME_KEY) {
            if dd_span.service.as_str() == service_name.as_str() {
                dd_span.meta.insert(
                    SpanStr::from_static_str(VERSION_KEY),
                    SpanStr::from_str(version),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libdd_trace_utils::span::vec_map::VecMap;

    fn chunk_with(priority: Option<f64>, error: i32) -> Vec<DdSpan<'static>> {
        let mut metrics = VecMap::new();
        if let Some(p) = priority {
            metrics.insert(SpanStr::from_static_str("_sampling_priority_v1"), p);
        }
        vec![DdSpan {
            error,
            metrics,
            ..Default::default()
        }]
    }

    #[test]
    fn chunk_is_sampled_honors_priority_without_error_retention() {
        // A dropped (priority <= 0) chunk is NOT sampled even when it contains an error span:
        // OTLP export must not apply libdatadog's error retention (that would leak spans dropped
        // by e.g. OTEL_TRACES_SAMPLER=parentbased_always_off).
        assert!(!chunk_is_sampled(&chunk_with(Some(-1.0), 1)));
        assert!(!chunk_is_sampled(&chunk_with(Some(0.0), 1)));
        // Kept chunks (priority > 0) are sampled.
        assert!(chunk_is_sampled(&chunk_with(Some(1.0), 0)));
        assert!(chunk_is_sampled(&chunk_with(Some(2.0), 1)));
        // A chunk with no priority is kept, mirroring libdatadog's send-path default.
        assert!(chunk_is_sampled(&chunk_with(None, 0)));
    }
}
