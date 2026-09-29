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

/// Chunk-level tag marking whether the trace chunk was exported through OTLP. Set to "false" on
/// the first span of every chunk exported natively to the Datadog agent.
const SDK_OTLP_EXPORT_KEY: &str = "_dd.sdk.otlp_export";

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
            sampling::priority::AUTO_KEEP.into_i8() as f64
        } else {
            sampling::priority::AUTO_REJECT.into_i8() as f64
        };
        dd_span.metrics.insert(priority_key, priority);
    }
}

// Transform a vector of opentelemetry span data into a vector of datadog tracechunks
pub fn otel_trace_chunk_to_dd_trace_chunk<'a, I>(
    cached_config: &'a CachedConfig,
    span_data: I,
    otel_resource: &'a Resource,
) -> Vec<DdSpan<'a>>
where
    I: IntoIterator<Item = &'a SpanData>,
{
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    let mut dd_spans: Vec<DdSpan<'a>> = span_data
        .into_iter()
        .map(|s| {
            let trace_flags = s.span_context.trace_flags();
            let sdk_span = SdkSpan::from_sdk_span_data(s);
            let mut dd_span = otel_span_to_dd_span(&sdk_span, otel_resource);
            otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);

            add_config_metadata(&mut dd_span, cached_config, otel_resource);

            dd_span
        })
        .collect();

    if let Some(first_span) = dd_spans.first_mut() {
        first_span.meta.insert(
            SpanStr::from_static_str(SDK_OTLP_EXPORT_KEY),
            SpanStr::from_static_str("false"),
        );
    }

    dd_spans
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
    use std::borrow::Cow;

    use opentelemetry::trace::{SpanContext, SpanId, TraceFlags, TraceId};
    use opentelemetry_sdk::trace::{SpanEvents, SpanLinks};

    use super::*;
    use crate::core::configuration::Config;

    fn span_data(span_id: u64, parent_span_id: u64) -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                TraceId::from(1u128),
                SpanId::from(span_id),
                TraceFlags::SAMPLED,
                false,
                Default::default(),
            ),
            parent_span_id: SpanId::from(parent_span_id),
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
    fn test_sdk_otlp_export_tag_only_on_first_span_of_chunk() {
        let cached_config = CachedConfig::new(&Config::builder().build());
        let resource = Resource::builder_empty().build();
        let spans = [span_data(1, 0), span_data(2, 1), span_data(3, 1)];

        let dd_spans = otel_trace_chunk_to_dd_trace_chunk(&cached_config, &spans, &resource);

        assert_eq!(dd_spans.len(), 3);
        assert_eq!(
            dd_spans[0]
                .meta
                .get(&SpanStr::from_static_str(SDK_OTLP_EXPORT_KEY))
                .map(|v| v.as_str()),
            Some("false")
        );
        for dd_span in &dd_spans[1..] {
            assert!(!dd_span
                .meta
                .contains_key(&SpanStr::from_static_str(SDK_OTLP_EXPORT_KEY)));
        }
    }

    #[test]
    fn test_sdk_otlp_export_tag_empty_chunk() {
        let cached_config = CachedConfig::new(&Config::builder().build());
        let resource = Resource::builder_empty().build();

        let dd_spans = otel_trace_chunk_to_dd_trace_chunk(&cached_config, &[], &resource);

        assert!(dd_spans.is_empty());
    }
}
