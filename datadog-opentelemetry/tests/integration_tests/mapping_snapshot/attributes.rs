// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Attribute coercion, semantic conventions, namespaces and reserved numeric flags.

use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{SpanBuilder, SpanKind, TracerProvider},
    InstrumentationScope, KeyValue, Value,
};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};

use super::{emit, resource, start_span, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Span attributes, aliases and namespace collisions
    MappingCase {
        name: "attributes__string_and_bool_meta",
        configure: None,
        resource: None,
        run: attributes_string_and_bool_meta,
    },
    MappingCase {
        name: "attributes__numeric_metrics",
        configure: None,
        resource: None,
        run: attributes_numeric_metrics,
    },
    MappingCase {
        name: "attributes__arrays_all_types",
        configure: None,
        resource: None,
        run: attributes_arrays_all_types,
    },
    MappingCase {
        name: "attributes__http_semconv_mappings",
        configure: None,
        resource: None,
        run: attributes_http_semconv_mappings,
    },
    MappingCase {
        name: "attributes__datadog_prefix_skipped",
        configure: None,
        resource: None,
        run: attributes_datadog_prefix_skipped,
    },
    MappingCase {
        name: "attributes__http_status_code_meta_protection",
        configure: None,
        resource: None,
        run: attributes_http_status_code_meta_protection,
    },
    MappingCase {
        name: "attributes__http_status_code_zero_metric",
        configure: None,
        resource: None,
        run: attributes_http_status_code_zero_metric,
    },
    MappingCase {
        name: "attributes__processor_priority_overrides_metric",
        configure: None,
        resource: None,
        run: attributes_processor_priority_overrides_metric,
    },
    MappingCase {
        name: "attributes__analytics_event_true",
        configure: None,
        resource: None,
        run: attributes_analytics_event_true,
    },
    MappingCase {
        name: "attributes__analytics_event_false",
        configure: None,
        resource: None,
        run: attributes_analytics_event_false,
    },
    MappingCase {
        name: "attributes__analytics_event_invalid",
        configure: None,
        resource: None,
        run: attributes_analytics_event_invalid,
    },
    MappingCase {
        name: "attributes__measured_string_protection",
        configure: None,
        resource: None,
        run: attributes_measured_string_protection,
    },
    MappingCase {
        name: "attributes__dd_measured_explicit",
        configure: None,
        resource: None,
        run: attributes_dd_measured_explicit,
    },
    MappingCase {
        name: "attributes__cross_source_namespace_collisions",
        configure: None,
        resource: Some(|| {
            resource(vec![
                KeyValue::new("resource-number", "resource string"),
                KeyValue::new("resource-bool", 123),
                KeyValue::new("shared", "resource"),
                KeyValue::new("env", "resource-env"),
                KeyValue::new("version", "resource-version"),
            ])
        }),
        run: namespace_collisions,
    },
    MappingCase {
        name: "attributes__numeric_flag_overwrite_matrix",
        configure: None,
        resource: None,
        run: numeric_flags,
    },
    // Resource attribute mapping
    MappingCase {
        name: "resource__attribute_mapping",
        configure: None,
        resource: Some(resource_attribute_mapping_res),
        run: resource_attribute_mapping,
    },
];

/// String and boolean span attributes map to string tags.
fn attributes_string_and_bool_meta(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("custom.string", "a string"),
            KeyValue::new("custom.bool_true", true),
            KeyValue::new("custom.bool_false", false),
        ],
    ));
}

/// Integer and float span attributes map to numeric tags.
fn attributes_numeric_metrics(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("custom.int", 42),
            KeyValue::new("custom.float", 1.5),
            KeyValue::new("custom.negative", -3),
        ],
    ));
}

/// Array attributes are flattened to `key.0`, `key.1`, ...: numbers become numeric
/// tags, strings and booleans become string tags.
fn attributes_arrays_all_types(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new(
                "arr.strings",
                Value::Array(vec![opentelemetry::StringValue::from("a"), "b".into()].into()),
            ),
            KeyValue::new("arr.ints", Value::Array(vec![1_i64, 2].into())),
            KeyValue::new("arr.floats", Value::Array(vec![1.5, 2.5].into())),
            KeyValue::new("arr.bools", Value::Array(vec![true, false].into())),
        ],
    ));
}

/// OTel semconv HTTP attribute keys are mapped to their Datadog equivalents
/// (http.client_ip, http.url, http.useragent, http.version, ...), including the
/// `http.request.header.*` prefix rewrite.
fn attributes_http_semconv_mappings(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![
            KeyValue::new("http.request.method", "GET"),
            KeyValue::new("client.address", "10.0.0.1"),
            KeyValue::new("http.response.body.size", 1024),
            KeyValue::new("http.request.body.size", 512),
            KeyValue::new("http.request.header.referrer", "https://referrer.example/"),
            KeyValue::new("url.full", "https://example.com/path"),
            KeyValue::new("user_agent.original", "test-agent/1.0"),
            KeyValue::new("server.address", "example.com"),
            KeyValue::new("network.protocol.version", "1.1"),
            KeyValue::new("http.request.header.x_custom", "header-value"),
        ],
    ));
}

/// Unknown `datadog.*` attributes are skipped entirely.
fn attributes_datadog_prefix_skipped(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("datadog.custom", "value"),
            KeyValue::new("datadog.other", 1),
        ],
    ));
}

/// The synthesized string `http.status_code` and numeric alias coexist in v0.4.
/// Preserve the string's meaning when migrating to a single v1 attribute namespace.
fn attributes_http_status_code_meta_protection(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 500)],
    ));
}

/// A zero `http.response.status_code` synthesizes no string tag, so the numeric
/// attribute survives as a metric under the mapped `http.status_code` key.
fn attributes_http_status_code_zero_metric(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("http.response.status_code", 0)],
    ));
}

/// The processor overwrites remapped `sampling.priority=0` with auto-keep (1).
fn attributes_processor_priority_overrides_metric(
    provider: &SdkTracerProvider,
    _: &dyn TextMapPropagator,
) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("sampling.priority", 0)],
    ));
}

/// `analytics.event=true` sets the analytics sample rate to 1.
fn attributes_analytics_event_true(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "true")],
    ));
}

/// `analytics.event` is parsed case-insensitively.
fn attributes_analytics_event_false(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "FALSE")],
    ));
}

/// An unparseable `analytics.event` value is ignored: no tag at all.
fn attributes_analytics_event_invalid(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![KeyValue::new("analytics.event", "maybe")],
    ));
}

/// A string `_dd.measured` attribute must not shadow the numeric `_dd.measured` flag
/// synthesized for client spans: libdatadog reads the flag as numeric-only.
fn attributes_measured_string_protection(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Client,
        vec![KeyValue::new("_dd.measured", "1")],
    ));
}

/// `_dd.measured=1` sets the measured flag on spans that don't get it from their kind.
fn attributes_dd_measured_explicit(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Server,
        vec![KeyValue::new("_dd.measured", 1)],
    ));
}

/// Ordinary strings overwrite by insertion order; protected tags retain the first
/// nonempty value. Numbers and strings coexist in v0.4, even on the same span.
fn namespace_collisions(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let scope = InstrumentationScope::builder("collision-scope")
        .with_attributes(vec![
            KeyValue::new("scope-number", "scope string"),
            KeyValue::new("shared", "scope"),
            KeyValue::new("env", "scope-env"),
            KeyValue::new("version", "scope-version"),
        ])
        .build();
    for reverse in [false, true] {
        let mut attrs = vec![
            KeyValue::new("resource-number", 42),
            KeyValue::new("scope-number", 43),
            KeyValue::new("resource-bool", true),
            KeyValue::new("shared", "span"),
            KeyValue::new("env", "span-env"),
            KeyValue::new("version", "span-version"),
            KeyValue::new("array", Value::Array(vec![1_i64, 2].into())),
            KeyValue::new("array.0", "scalar string"),
            KeyValue::new(
                "strings",
                Value::Array(vec![opentelemetry::StringValue::from("flattened")].into()),
            ),
            KeyValue::new("strings.0", "scalar last"),
            KeyValue::new("empty", Value::Array(Vec::<i64>::new().into())),
            KeyValue::new("http.method", "OLD"),
            KeyValue::new("http.request.method", "NEW"),
            KeyValue::new("http.request.header.referrer", "special"),
            KeyValue::new("http.referrer", "literal"),
            KeyValue::new("_dd.measured", "string flag"),
            KeyValue::new("_top_level", "string top level"),
            KeyValue::new("_sampling_priority_v1", "string priority"),
            KeyValue::new("_dd1.sr.eausr", "string analytics"),
            KeyValue::new("analytics.event", "true"),
        ];
        if reverse {
            attrs.reverse();
        }
        drop(
            SpanBuilder::from_name(format!("reverse={reverse}"))
                .with_kind(SpanKind::Client)
                .with_attributes(attrs)
                .start(&provider.tracer_with_scope(scope.clone())),
        );
    }
}

/// Numeric inputs can overwrite converter flags; later processor/writer handling
/// can overwrite them again. Strings coexist rather than replacing numbers in v0.4.
fn numeric_flags(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for kind in [
        SpanKind::Client,
        SpanKind::Server,
        SpanKind::Producer,
        SpanKind::Internal,
    ] {
        for value in [
            Value::I64(0),
            Value::I64(1),
            Value::I64(-1),
            Value::from("string"),
        ] {
            emit(
                provider,
                &format!("{kind:?}:{value:?}"),
                kind.clone(),
                vec![
                    KeyValue::new("_dd.measured", value.clone()),
                    KeyValue::new("_top_level", value.clone()),
                    KeyValue::new("_sampling_priority_v1", value.clone()),
                    KeyValue::new("_dd1.sr.eausr", value),
                ],
            );
        }
    }
}

/// Resource attributes go through the same semconv key mapping as span attributes
/// (`url.full` -> `http.url`, ...); unknown keys are kept as-is.
fn resource_attribute_mapping(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![],
    ));
}

fn resource_attribute_mapping_res() -> Resource {
    resource(vec![
        KeyValue::new("url.full", "https://datadoghq.com"),
        KeyValue::new("custom.resource_attr", "resource-value"),
        KeyValue::new("http.request.header.x_res", "res-header"),
    ])
}
