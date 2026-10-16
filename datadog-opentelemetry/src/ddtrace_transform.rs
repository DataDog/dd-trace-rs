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

    apply_http_error_statuses(dd_span, cached_config);
}

/// Server and client spans with an HTTP status code are errors if, and only if, the code is
/// in `DD_TRACE_HTTP_SERVER_ERROR_STATUSES` or `DD_TRACE_HTTP_CLIENT_ERROR_STATUSES`. This
/// overrides the OpenTelemetry span status, as in the other Datadog SDKs.
fn apply_http_error_statuses(dd_span: &mut DdSpan, cached_config: &CachedConfig) {
    let error_statuses = match dd_span
        .meta
        .get(&SpanStr::from_static_str("span.kind"))
        .map(SpanStr::as_str)
    {
        Some("server") => &cached_config.http_server_error_statuses,
        Some("client") => &cached_config.http_client_error_statuses,
        _ => return,
    };
    let Some(status_code) = dd_span
        .meta
        .get(&SpanStr::from_static_str("http.status_code"))
        .and_then(|code| code.as_str().parse::<u16>().ok())
    else {
        return;
    };
    let was_error = dd_span.error != 0;
    dd_span.error = i32::from(error_statuses.contains(status_code));
    if was_error && dd_span.error == 0 {
        // The error tags describe the error that was just cleared. Any exception details are
        // still in the span events.
        for key in ["error.message", "error.type", "error.stack"] {
            dd_span.meta.remove_slow(&SpanStr::from_static_str(key));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::configuration::Config;

    fn span(kind: &'static str, status_code: Option<&'static str>, error: i32) -> DdSpan<'static> {
        let mut span = DdSpan {
            error,
            ..Default::default()
        };
        span.meta.insert(
            SpanStr::from_static_str("span.kind"),
            SpanStr::from_static_str(kind),
        );
        if let Some(code) = status_code {
            span.meta.insert(
                SpanStr::from_static_str("http.status_code"),
                SpanStr::from_static_str(code),
            );
        }
        span
    }

    fn error_after(cached_config: &CachedConfig, mut span: DdSpan) -> i32 {
        apply_http_error_statuses(&mut span, cached_config);
        span.error
    }

    #[test]
    fn test_default_http_error_statuses() {
        let cached_config = CachedConfig::new(&Config::builder().build());

        assert_eq!(
            error_after(&cached_config, span("server", Some("500"), 0)),
            1
        );
        assert_eq!(
            error_after(&cached_config, span("server", Some("404"), 1)),
            0
        );
        assert_eq!(
            error_after(&cached_config, span("client", Some("404"), 0)),
            1
        );
        assert_eq!(
            error_after(&cached_config, span("client", Some("500"), 1)),
            0
        );
    }

    #[test]
    fn test_http_error_statuses_clear_error_tags() {
        let cached_config = CachedConfig::new(&Config::builder().build());
        let error_tags = ["error.message", "error.type", "error.stack"];
        let with_error_tags = |code| {
            let mut span = span("server", Some(code), 1);
            for key in error_tags {
                span.meta.insert(
                    SpanStr::from_static_str(key),
                    SpanStr::from_static_str("boom"),
                );
            }
            span
        };

        // Cleared error: the tags go with it
        let mut cleared = with_error_tags("404");
        apply_http_error_statuses(&mut cleared, &cached_config);
        assert_eq!(cleared.error, 0);
        for key in error_tags {
            assert!(
                cleared.meta.get(&SpanStr::from_static_str(key)).is_none(),
                "{key} should be removed"
            );
        }

        // Kept error: the tags stay
        let mut kept = with_error_tags("500");
        apply_http_error_statuses(&mut kept, &cached_config);
        assert_eq!(kept.error, 1);
        for key in error_tags {
            assert!(
                kept.meta.get(&SpanStr::from_static_str(key)).is_some(),
                "{key} should be kept"
            );
        }
    }

    #[test]
    fn test_http_error_statuses_leave_other_spans_alone() {
        let cached_config = CachedConfig::new(&Config::builder().build());

        // No status code, e.g. a failed connection
        assert_eq!(error_after(&cached_config, span("client", None, 1)), 1);
        assert_eq!(
            error_after(&cached_config, span("internal", Some("500"), 0)),
            0
        );
        assert_eq!(
            error_after(&cached_config, span("producer", Some("200"), 1)),
            1
        );
    }
}
