// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Propagated trace context, instrumentation scope and span-link values.

use std::str::FromStr;

use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{Link, SpanBuilder, SpanContext, SpanKind, TraceFlags, TraceState, TracerProvider},
    InstrumentationScope, KeyValue, SpanId, TraceId, Value,
};
use opentelemetry_sdk::trace::SdkTracerProvider;

use super::{make_extractor, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Propagated context and instrumentation scope
    MappingCase {
        name: "context__datadog_tracestate_propagated",
        configure: None,
        resource: None,
        run: context_datadog_tracestate_propagated,
    },
    MappingCase {
        name: "context__scope_name_version_attributes",
        configure: None,
        resource: None,
        run: context_scope_name_version_attributes,
    },
    // Link attributes, tracestate and flags
    MappingCase {
        name: "links__variants",
        configure: None,
        resource: None,
        run: links_variants,
    },
    MappingCase {
        name: "links__scalar_flags_and_empty_arrays",
        configure: None,
        resource: None,
        run: link_scalar_edges,
    },
];

/// Extraction retains Datadog origin, decision maker and propagated tags, but the
/// public pipeline does not retain SDK span tracestate (`w3c.tracestate` is absent).
fn context_datadog_tracestate_propagated(
    provider: &SdkTracerProvider,
    propagator: &dyn TextMapPropagator,
) {
    let parent = propagator.extract(&make_extractor([
        (
            "traceparent",
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01",
        ),
        (
            "tracestate",
            "dd=p:00f067aa0ba902b7;s:2;o:rum;t.dm:-4;t.usr.id:baz64",
        ),
    ]));
    let _guard = parent.attach();
    drop(
        SpanBuilder::from_name("tracestate-child")
            .with_kind(SpanKind::Server)
            .start(&provider.tracer("mapping")),
    );
}

/// The instrumentation scope name and version become `otel.scope.name` and
/// `otel.scope.version`, and the scope attributes are mapped as span tags.
fn context_scope_name_version_attributes(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let scope = InstrumentationScope::builder("my-lib")
        .with_version("4.5.6")
        .with_attributes(vec![
            KeyValue::new("scope.attr", "scope-value"),
            KeyValue::new("scope.team", "platform"),
        ])
        .build();
    drop(
        SpanBuilder::from_name("scoped-span")
            .with_kind(SpanKind::Internal)
            .start(&provider.tracer_with_scope(scope)),
    );
}

/// Links keep stringified, flattened attributes, their tracestate and W3C trace
/// flags; the 128-bit trace id is preserved.
fn links_variants(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let sampled_context = |trace_state: TraceState| {
        SpanContext::new(
            TraceId::from_hex("fedcba98765432100123456789abcdef").unwrap(),
            SpanId::from_hex("abcdef0123456789").unwrap(),
            TraceFlags::SAMPLED,
            false,
            trace_state,
        )
    };
    let links = vec![
        Link::new(
            sampled_context(TraceState::from_str("dd=s:2,ee=jkl;128").unwrap()),
            vec![KeyValue::new("link.attr", "value")],
            0,
        ),
        Link::new(
            sampled_context(TraceState::default()),
            vec![
                KeyValue::new(
                    "strings",
                    Value::Array(vec![opentelemetry::StringValue::from("a"), "b".into()].into()),
                ),
                KeyValue::new("bools", Value::Array(vec![true, false].into())),
                KeyValue::new("ints", Value::Array(vec![1_i64, 2].into())),
                KeyValue::new("floats", Value::Array(vec![1.5].into())),
            ],
            0,
        ),
        Link::new(
            SpanContext::new(
                TraceId::from_hex("abcdef0123456789abcdef0123456789").unwrap(),
                SpanId::from_hex("fedcba9876543210").unwrap(),
                TraceFlags::default(),
                false,
                TraceState::default(),
            ),
            vec![],
            0,
        ),
    ];
    drop(
        SpanBuilder::from_name("span-with-links")
            .with_kind(SpanKind::Internal)
            .with_links(links)
            .start(&provider.tracer("mapping")),
    );
}

fn link_scalar_edges(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    let context = opentelemetry::trace::SpanContext::new(
        opentelemetry::TraceId::from(1),
        opentelemetry::SpanId::from(2),
        opentelemetry::trace::TraceFlags::new(0xfe),
        false,
        Default::default(),
    );
    let links = vec![opentelemetry::trace::Link::new(
        context,
        vec![
            KeyValue::new("int", -7),
            KeyValue::new("float", 1.5),
            KeyValue::new("bool", false),
            KeyValue::new("empty", Value::Array(Vec::<i64>::new().into())),
            KeyValue::new("empty-bools", Value::Array(Vec::<bool>::new().into())),
            KeyValue::new("empty-floats", Value::Array(Vec::<f64>::new().into())),
            KeyValue::new(
                "empty-strings",
                Value::Array(Vec::<opentelemetry::StringValue>::new().into()),
            ),
        ],
        0,
    )];
    drop(
        SpanBuilder::from_name("link-edge-flags")
            .with_links(links)
            .start(&provider.tracer("mapping")),
    );
}
