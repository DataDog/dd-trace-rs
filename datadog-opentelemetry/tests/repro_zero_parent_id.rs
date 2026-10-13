// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;

use datadog_opentelemetry::configuration::{Config, SamplingRuleConfig};
use datadog_opentelemetry::make_test_tracer;
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::{Span, SpanBuilder, TraceId, Tracer, TracerProvider};

fn build_child_trace_id(headers: &[(&str, &str)]) -> TraceId {
    let mut cfg = Config::builder();
    cfg.set_trace_sampling_rules(vec![SamplingRuleConfig {
        sample_rate: 0.0,
        ..SamplingRuleConfig::default()
    }]);
    let (tracer_provider, propagator) = make_test_tracer(Arc::new(cfg.build()));

    let carrier: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let parent_cx = propagator.extract(&carrier);

    let tracer = tracer_provider.tracer("repro");
    let mut span = tracer.build_with_context(SpanBuilder::from_name("name"), &parent_cx);
    let trace_id = span.span_context().trace_id();
    span.end();
    trace_id
}

#[tokio::test]
async fn zero_parent_id_keeps_incoming_trace_id() {
    let trace_id = build_child_trace_id(&[
        ("x-datadog-trace-id", "123456789"),
        ("x-datadog-parent-id", "0"),
        ("x-datadog-sampling-priority", "1"),
        ("x-datadog-origin", "synthetics;=web,z"),
    ]);
    assert_eq!(trace_id, TraceId::from(123456789u128));
}

#[tokio::test]
async fn nonzero_parent_id_keeps_incoming_trace_id() {
    let trace_id = build_child_trace_id(&[
        ("x-datadog-trace-id", "123456789"),
        ("x-datadog-parent-id", "987654321"),
        ("x-datadog-sampling-priority", "1"),
        ("x-datadog-origin", "synthetics;=web,z"),
    ]);
    assert_eq!(trace_id, TraceId::from(123456789u128));
}
