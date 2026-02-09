// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::core::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::sampling::OtelSamplingData;
use datadog_opentelemetry::sampling::SamplingRule;
use datadog_opentelemetry::sampling::{DatadogSampler, SamplingData};
use opentelemetry::{trace::SpanKind, KeyValue, TraceId};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, RwLock};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

struct BenchmarkConfig {
    name: &'static str,
    rules: Vec<SamplingRule>,
    resource: opentelemetry_sdk::Resource,
    trace_id: TraceId,
    span_name: &'static str,
    span_kind: SpanKind,
    attributes: Vec<KeyValue>,
    is_parent_sampled: Option<bool>,
    should_keep: Option<bool>,
}

fn create_benchmark_configs() -> Vec<BenchmarkConfig> {
    let trace_id = TraceId::from(0x12345678901234567890123456789012_u128);

    vec![
        // 1. All spans rule (baseline)
        BenchmarkConfig {
            name: "rule_all_spans_only_rate",
            rules: vec![SamplingRule::new(1.0, None, None, None, None, None)],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "something",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar"), KeyValue::new("bar", "baz")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 2. Service rule - matching
        BenchmarkConfig {
            name: "service_rule_matching",
            rules: vec![SamplingRule::new(
                1.0,
                Some("test-service".to_string()),
                None,
                None,
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 3. Service rule - not matching
        BenchmarkConfig {
            name: "service_rule_not_matching",
            rules: vec![SamplingRule::new(
                1.0,
                Some("test-service".to_string()),
                None,
                None,
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("other-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 4. Name pattern rule - matching
        BenchmarkConfig {
            name: "name_pattern_rule_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                Some("http.*".to_string()),
                None,
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("http.method", "GET")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 5. Name pattern rule - not matching
        BenchmarkConfig {
            name: "name_pattern_rule_not_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                Some("http.*".to_string()),
                None,
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "grpc.request",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("rpc.method", "GetUser")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 6. Resource pattern rule - matching
        BenchmarkConfig {
            name: "resource_pattern_rule_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                None,
                Some("/api/*".to_string()),
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("http.method", "GET"),
                KeyValue::new("http.route", "/api/users"),
            ],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 7. Resource pattern rule - not matching
        BenchmarkConfig {
            name: "resource_pattern_rule_not_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                None,
                Some("/api/*".to_string()),
                None,
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("http.method", "GET"),
                KeyValue::new("http.route", "/health"),
            ],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 8. Tag rule - matching
        BenchmarkConfig {
            name: "tag_rule_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                None,
                None,
                Some(HashMap::from([(
                    "environment".to_string(),
                    "production".to_string(),
                )])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "production"),
                KeyValue::new("foo", "bar"),
            ],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 9. Tag rule - not matching
        BenchmarkConfig {
            name: "tag_rule_not_matching",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                None,
                None,
                Some(HashMap::from([(
                    "environment".to_string(),
                    "production".to_string(),
                )])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "staging"),
                KeyValue::new("foo", "bar"),
            ],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 10. Complex rule - matching
        BenchmarkConfig {
            name: "complex_rule_matching",
            rules: vec![SamplingRule::new(
                0.5,
                Some("api-service".to_string()),
                Some("http.*".to_string()),
                Some("/api/v1/*".to_string()),
                Some(HashMap::from([(
                    "environment".to_string(),
                    "production".to_string(),
                )])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("api-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "production"),
                KeyValue::new("http.method", "POST"),
                KeyValue::new("http.route", "/api/v1/users"),
            ],
            is_parent_sampled: None,
            should_keep: None, // Probabilistic sampling at 0.5 rate
        },
        // 11. Complex rule - partial match
        BenchmarkConfig {
            name: "complex_rule_partial_match",
            rules: vec![SamplingRule::new(
                0.5,
                Some("api-service".to_string()),
                Some("http.*".to_string()),
                Some("/api/v1/*".to_string()),
                Some(HashMap::from([(
                    "environment".to_string(),
                    "production".to_string(),
                )])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("api-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "staging"),
                KeyValue::new("http.method", "POST"),
                KeyValue::new("http.route", "/health"),
            ],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 12. Multiple rules - first match
        BenchmarkConfig {
            name: "multiple_rules_first_match",
            rules: vec![
                SamplingRule::new(0.1, Some("api-service".to_string()), None, None, None, None),
                SamplingRule::new(0.5, Some("web-service".to_string()), None, None, None, None),
                SamplingRule::new(1.0, None, None, None, None, None),
            ],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("api-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            is_parent_sampled: None,
            should_keep: None, // Probabilistic sampling at 0.1 rate
        },
        // 13. Multiple rules - last match
        BenchmarkConfig {
            name: "multiple_rules_last_match",
            rules: vec![
                SamplingRule::new(0.1, Some("api-service".to_string()), None, None, None, None),
                SamplingRule::new(0.5, Some("web-service".to_string()), None, None, None, None),
                SamplingRule::new(1.0, None, None, None, None, None),
            ],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("other-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 14. Many attributes
        BenchmarkConfig {
            name: "many_attributes",
            rules: vec![SamplingRule::new(
                1.0,
                None,
                None,
                None,
                Some(HashMap::from([(
                    "key10".to_string(),
                    "value10".to_string(),
                )])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: (0..20)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            is_parent_sampled: None,
            should_keep: Some(true),
        },
        // 15. Parent sampled - short circuit with many attributes and complex rules
        BenchmarkConfig {
            name: "parent_sampled_short_circuit",
            rules: vec![SamplingRule::new(
                1.0,
                Some("test-service".to_string()),
                Some("http.*".to_string()),
                Some("/api/*".to_string()),
                Some(HashMap::from([
                    ("environment".to_string(), "production".to_string()),
                    ("region".to_string(), "us-east-1".to_string()),
                    ("version".to_string(), "v1.2.3".to_string()),
                ])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: (0..50)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            is_parent_sampled: Some(true),
            should_keep: Some(true),
        },
        // 16. Parent not sampled - short circuit with many attributes and complex rules
        BenchmarkConfig {
            name: "parent_not_sampled_short_circuit",
            rules: vec![SamplingRule::new(
                1.0,
                Some("test-service".to_string()),
                Some("http.*".to_string()),
                Some("/api/*".to_string()),
                Some(HashMap::from([
                    ("environment".to_string(), "production".to_string()),
                    ("region".to_string(), "us-east-1".to_string()),
                    ("version".to_string(), "v1.2.3".to_string()),
                ])),
                None,
            )],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: (0..50)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            is_parent_sampled: Some(false),
            should_keep: Some(false),
        },
    ]
}

fn bench_datadog_sampling<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let configs = create_benchmark_configs();

    for config in configs {
        let sampler = DatadogSampler::new(config.rules, -1, Arc::new(RwLock::new(config.resource)));
        let data = OtelSamplingData::new(
            black_box(config.is_parent_sampled),
            black_box(&config.trace_id),
            black_box(config.span_name),
            black_box(config.span_kind.clone()),
            black_box(&config.attributes),
            black_box(sampler.resource()),
        );

        c.bench_function(
            &format!("datadog_sample_span/{}/{}", config.name, M::name()),
            |b| {
                b.iter_batched(
                    || (),
                    |_| {
                        bench_sample(&sampler, &data, config.should_keep);
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }
}

#[inline(never)]
fn bench_sample(sampler: &DatadogSampler, data: &impl SamplingData, should_keep: Option<bool>) {
    let result = black_box(sampler).sample(black_box(data));
    if let Some(should_keep) = should_keep {
        assert_eq!(result.get_priority().is_keep(), should_keep);
        black_box(result);
    } else {
        black_box(result);
    }
}

criterion_group!(
    name = memory_benches;
    config = memory_allocated_measurement(&GLOBAL);
    targets = bench_datadog_sampling
);
criterion_group!(
    name = wall_time_benches;
    config = Criterion::default();
    targets = bench_datadog_sampling
);
criterion_main!(memory_benches, wall_time_benches);
