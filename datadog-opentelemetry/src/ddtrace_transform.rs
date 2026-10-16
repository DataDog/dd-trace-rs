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
use bumpalo::Bump;
use libdd_trace_utils::span::span_pool::SpanPool;
use libdd_trace_utils::span::SpanText;
use opentelemetry::{trace::SpanId, Key};
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
    span_pool: &SpanPool<SpanStr<'a>>,
    alloc: &'a Bump,
) -> Vec<DdSpan<'a>>
where
    I: IntoIterator<Item = &'a SpanData>,
{
    // TODO: This can maybe faster by sorting the span_data by trace_id
    // and then handing off groups of span data?
    // Pull a recycled chunk from the pool (retained capacity) instead of allocating
    // a fresh Vec; it will be handed back to the pool when the PooledChunks is dropped.
    let mut chunk = span_pool.pull_empty_chunk();
    chunk.extend(span_data.into_iter().map(|s| {
        let trace_flags = s.span_context.trace_flags();
        let sdk_span = SdkSpan::from_sdk_span_data(s);

        let mut dd_span = span_pool.get_span();
        otel_span_to_dd_span(&mut dd_span, &sdk_span, otel_resource, alloc);
        otel_sampling_to_dd_sampling(trace_flags, &mut dd_span);

        add_config_metadata(&mut dd_span, cached_config, otel_resource);
        if s.parent_span_id == SpanId::INVALID || s.parent_span_is_remote {
            add_local_root_metadata(&mut dd_span, cached_config);
        }

        dd_span
    }));
    chunk
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

/// Tags that the Datadog SDKs set on the local root span of each trace chunk.
fn add_local_root_metadata<'a>(dd_span: &mut DdSpan<'a>, cached_config: &'a CachedConfig) {
    dd_span.meta.insert(
        SpanStr::from_static_str("language"),
        SpanStr::from_str(&cached_config.language),
    );
    dd_span.meta.insert(
        SpanStr::from_static_str("runtime-id"),
        SpanStr::from_str(&cached_config.runtime_id),
    );
    dd_span.metrics.insert(
        SpanStr::from_static_str("process_id"),
        cached_config.process_id,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::configuration::Config;
    use opentelemetry::trace::{SpanContext, TraceFlags, TraceId};
    use opentelemetry_sdk::trace::{SpanEvents, SpanLinks};
    use std::borrow::Cow;

    fn span_data(span_id: u64, parent_span_id: u64, parent_span_is_remote: bool) -> SpanData {
        SpanData {
            span_context: SpanContext::new(
                TraceId::from(1),
                SpanId::from(span_id),
                TraceFlags::SAMPLED,
                false,
                Default::default(),
            ),
            parent_span_id: SpanId::from(parent_span_id),
            parent_span_is_remote,
            span_kind: opentelemetry::trace::SpanKind::Internal,
            name: Cow::Borrowed("span"),
            start_time: std::time::SystemTime::now(),
            end_time: std::time::SystemTime::now(),
            attributes: Vec::new(),
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: opentelemetry::trace::Status::Unset,
            instrumentation_scope: Default::default(),
        }
    }

    #[test]
    fn test_local_root_metadata() {
        let config = Config::builder().build();
        let cached_config = CachedConfig::new(&config);
        let resource = Resource::builder_empty().build();
        let alloc = Bump::new();
        let span_data = [
            span_data(1, 0, false), // local root of a new trace
            span_data(2, 1, false), // its child
            span_data(3, 99, true), // local root continuing a remote trace
        ];

        // Declared last: the pooled spans borrow from everything above
        let span_pool = SpanPool::with_capacity(10);
        let chunk = otel_trace_chunk_to_dd_trace_chunk(
            &cached_config,
            &span_data,
            &resource,
            &span_pool,
            &alloc,
        );

        assert_eq!(chunk.len(), 3);
        let process_id = f64::from(std::process::id());
        for (span, is_local_root) in chunk.iter().zip([true, false, true]) {
            let meta = |key| {
                span.meta
                    .get(&SpanStr::from_static_str(key))
                    .map(SpanStr::as_str)
            };
            let process_id_metric = span
                .metrics
                .get(&SpanStr::from_static_str("process_id"))
                .copied();
            if is_local_root {
                assert_eq!(meta("language"), Some("rust"), "span {}", span.span_id);
                assert_eq!(meta("runtime-id"), Some(config.runtime_id()));
                assert_eq!(process_id_metric, Some(process_id));
            } else {
                assert_eq!(meta("language"), None, "span {}", span.span_id);
                assert_eq!(meta("runtime-id"), None);
                assert_eq!(process_id_metric, None);
            }
        }
    }
}
