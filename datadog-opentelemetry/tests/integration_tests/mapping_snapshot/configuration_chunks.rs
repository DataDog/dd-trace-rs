// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Configured global metadata, completion order, partial flush and local roots.

use datadog_opentelemetry::configuration::ConfigBuilder;
use opentelemetry::{
    propagation::TextMapPropagator,
    trace::{SpanBuilder, SpanKind, TraceContextExt, TracerProvider},
    Context, KeyValue,
};
use opentelemetry_sdk::trace::SdkTracerProvider;

use super::{ignored_name_span, resource, start_span, MappingCase};

pub(super) const CASES: &[MappingCase] = &[
    // Chunk and local-root metadata
    MappingCase {
        name: "chunk__origin_and_tid",
        configure: None,
        resource: None,
        run: chunk_origin_and_tid,
    },
    MappingCase {
        name: "chunk__partial_flush_root_child_metadata",
        configure: Some(|cfg| {
            cfg.set_trace_partial_flush_enabled(true)
                .set_trace_partial_flush_min_spans(1);
        }),
        resource: None,
        run: root_child_completion,
    },
    MappingCase {
        name: "chunk__remote_root_and_child",
        configure: None,
        resource: None,
        run: remote_root_and_child,
    },
    // Configured global metadata
    // Global tags from the configuration are applied to every span.
    MappingCase {
        name: "config__global_tags",
        configure: Some(config_global_tags_config),
        resource: None,
        run: ignored_name_span,
    },
    MappingCase {
        name: "config__root_child_global_tag_version_conflicts",
        configure: Some(|cfg| {
            cfg.set_global_tags(vec![
                ("shared".into(), "global".into()),
                ("version".into(), "global-version".into()),
            ])
            .set_version("config-version".into())
            .set_env("config-env".into());
        }),
        resource: Some(|| {
            resource(vec![
                KeyValue::new("service.name", "app"),
                KeyValue::new("service.version", "resource-version"),
                KeyValue::new("deployment.environment.name", "resource-env"),
            ])
        }),
        run: root_child_completion,
    },
];

/// `_dd.origin` and `_dd.p.dm` on the local root are lifted to chunk-level fields;
/// the `_dd.p.tid` high bits of the trace id are consumed into the chunk trace id and
/// removed from the span tags.
fn chunk_origin_and_tid(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    drop(start_span(
        provider,
        "ignored-name",
        SpanKind::Internal,
        vec![
            KeyValue::new("_dd.origin", "synthetics"),
            KeyValue::new("_dd.p.tid", "00000000000000ff"),
        ],
    ));
}

/// Children complete before the root, or after it. Metadata must follow actual
/// local-root identity, not position in the completed chunk.
fn root_child_completion(provider: &SdkTracerProvider, _: &dyn TextMapPropagator) {
    for root_first in [false, true] {
        let root = SpanBuilder::from_name(format!("root:first={root_first}"))
            .with_attributes(vec![
                KeyValue::new("shared", "root"),
                KeyValue::new("datadog.version", "root-version"),
            ])
            .start(&provider.tracer("mapping"));
        let cx = Context::new().with_span(root);
        let child = SpanBuilder::from_name(format!("child:first={root_first}"))
            .with_attributes(vec![
                KeyValue::new("shared", "child"),
                KeyValue::new("datadog.service", "child-service"),
                KeyValue::new("datadog.version", "child-version"),
            ])
            .start_with_context(&provider.tracer("mapping"), &cx);
        if root_first {
            cx.span().end();
        }
        drop(child);
        cx.span().end();
    }
}

fn remote_root_and_child(provider: &SdkTracerProvider, propagator: &dyn TextMapPropagator) {
    let remote = propagator.extract(&super::make_extractor([
        (
            "traceparent",
            "00-80f198ee56343ba864fe8b2a57d3eff7-00f067aa0ba902b7-01",
        ),
        ("tracestate", "dd=s:2;o:rum;t.dm:-4;t.usr.id:baz64"),
    ]));
    let root = SpanBuilder::from_name("remote-local-root")
        .start_with_context(&provider.tracer("mapping"), &remote);
    let local = Context::new().with_span(root);
    drop(
        SpanBuilder::from_name("local-child")
            .start_with_context(&provider.tracer("mapping"), &local),
    );
    local.span().end();
}

fn config_global_tags_config(cfg: &mut ConfigBuilder) {
    cfg.set_global_tags(vec![
        ("team".to_string(), "apm".to_string()),
        ("custom.gtag".to_string(), "gv".to_string()),
    ]);
}
