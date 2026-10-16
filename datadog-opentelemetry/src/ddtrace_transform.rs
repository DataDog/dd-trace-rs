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
use opentelemetry::{trace::SpanId, Key, Value};
use opentelemetry_sdk::{trace::SpanData, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;

static SERVICE_NAME_KEY: Key = Key::from_static_str(SERVICE_NAME);

const BASE_SERVICE_KEY: &str = "_dd.base_service";

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

/// The resolved application service. The cached config is built before the resource is set,
/// so it doesn't know about a `service.name` coming from the OpenTelemetry resource.
fn application_service<'a>(
    cached_config: &'a CachedConfig,
    otel_resource: &'a Resource,
) -> &'a str {
    match otel_resource.get_ref(&SERVICE_NAME_KEY) {
        Some(Value::String(service)) if !service.as_str().is_empty() => service.as_str(),
        _ => &cached_config.service,
    }
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

    // Spans whose service was overridden keep a reference to the application service
    let base_service = application_service(cached_config, otel_resource);
    if !dd_span.service.as_str().is_empty() && dd_span.service.as_str() != base_service {
        dd_span.meta.insert(
            SpanStr::from_static_str(BASE_SERVICE_KEY),
            SpanStr::from_str(base_service),
        );
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

    fn base_service_with(
        dd_service: Option<&str>,
        resource_service: Option<&'static str>,
        span_service: &'static str,
    ) -> Option<String> {
        let mut config = Config::builder();
        if let Some(service) = dd_service {
            config.set_service(service.to_string());
        }
        let cached_config = CachedConfig::new(&config.build());
        let mut otel_resource = Resource::builder_empty();
        if let Some(service) = resource_service {
            otel_resource = otel_resource.with_service_name(service);
        }
        let otel_resource = otel_resource.build();

        let mut span = DdSpan {
            service: SpanStr::from_static_str(span_service),
            ..Default::default()
        };
        add_config_metadata(&mut span, &cached_config, &otel_resource);
        span.meta
            .get(&SpanStr::from_static_str(BASE_SERVICE_KEY))
            .map(|v| v.as_str().to_string())
    }

    fn base_service(span_service: &'static str) -> Option<String> {
        base_service_with(Some("global-service"), None, span_service)
    }

    #[test]
    fn test_base_service() {
        assert_eq!(
            base_service("other-service").as_deref(),
            Some("global-service")
        );
        assert_eq!(base_service("global-service"), None);
        // Replaced by the global service
        assert_eq!(base_service(DEFAULT_OTLP_SERVICE_NAME), None);
    }

    #[test]
    fn test_base_service_from_resource() {
        // DD_SERVICE unset: the resource's service.name is the application service
        assert_eq!(
            base_service_with(None, Some("otel-service"), "otel-service"),
            None
        );
        assert_eq!(
            base_service_with(None, Some("otel-service"), "other-service").as_deref(),
            Some("otel-service")
        );
    }

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
