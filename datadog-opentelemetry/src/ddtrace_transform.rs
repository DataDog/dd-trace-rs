// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to dd-trace

use std::collections::hash_map;

use crate::{
    core::sampling,
    mappings::{
        otel_span_to_dd_span, CachedConfig, DdSpan, SdkSpan, SpanStr, DEFAULT_OTLP_SERVICE_NAME,
        VERSION_KEY,
    },
};
use datadog_trace_utils::span::SpanText;
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
    if let hash_map::Entry::Vacant(e) = dd_span
        .metrics
        .entry(SpanStr::from_static_str("_sampling_priority_v1"))
    {
        if otel_trace_flags.is_sampled() {
            e.insert(sampling::priority::AUTO_KEEP.into_i8() as f64);
        } else {
            e.insert(sampling::priority::AUTO_REJECT.into_i8() as f64);
        }
    }
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
    if dd_span.service.as_str() == DEFAULT_OTLP_SERVICE_NAME {
        dd_span.service = SpanStr::from_str(cached_config.service());
    }

    for (key, value) in cached_config.global_tags() {
        dd_span
            .meta
            .insert(SpanStr::from_str(key), SpanStr::from_str(value));
    }

    if let Some(version) = cached_config.version() {
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
