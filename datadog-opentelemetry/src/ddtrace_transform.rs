// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! This module contains trace mapping from otel to datadog
//! specific to dd-trace

use std::collections::hash_map;

use datadog_opentelemetry_mappings::SdkSpan;
use datadog_trace_utils::span::SpanBytes as DdSpan;
use dd_trace::sampling;
use opentelemetry::Key;
use opentelemetry_sdk::{trace::SpanData, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tinybytes::BytesString;

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
        .entry(BytesString::from_static("_sampling_priority_v1"))
    {
        if otel_trace_flags.is_sampled() {
            e.insert(sampling::priority::AUTO_KEEP.into_i8() as f64);
        } else {
            e.insert(sampling::priority::AUTO_REJECT.into_i8() as f64);
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
            let mut dd_span = datadog_opentelemetry_mappings::otel_span_to_dd_span(
                SdkSpan::from_sdk_span_data(s),
                otel_resource,
            );
            otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);

            add_config_metadata(&mut dd_span, cfg, otel_resource);

            dd_span
        })
        .collect()
}

fn add_config_metadata(dd_span: &mut DdSpan, cfg: &dd_trace::Config, otel_resource: &Resource) {
    if dd_span.service == datadog_opentelemetry_mappings::DEFAULT_OTLP_SERVICE_NAME {
        dd_span.service = BytesString::from_string(cfg.service().to_string());
    }

    cfg.global_tags().for_each(|tag| {
        dd_span.meta.insert(
            BytesString::from_string(tag.0.to_string()),
            BytesString::from_string(tag.1.to_string()),
        );
    });

    if let Some(env) = cfg.env() {
        dd_span.meta.insert(
            BytesString::from_static("env"),
            BytesString::from_string(env.to_string()),
        );
    }

    if let Some(version) = cfg.version() {
        if let Some(service_name) = otel_resource.get(&SERVICE_NAME_KEY) {
            if dd_span.service.as_str() == service_name.as_str() {
                dd_span.meta.insert(
                    BytesString::from_static("version"),
                    BytesString::from_string(version.to_string()),
                );
            }
        }
    }
}
