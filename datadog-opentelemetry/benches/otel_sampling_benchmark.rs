// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::configuration::{Config, SamplingRuleConfig};
use datadog_opentelemetry::core::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::sampler::Sampler;
use opentelemetry::{trace::SamplingDecision, trace::SpanKind, KeyValue, TraceId};
use opentelemetry_sdk::trace::ShouldSample;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, RwLock};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

struct BenchmarkConfig {
    name: &'static str,
    rules: Vec<SamplingRuleConfig>,
    resource: opentelemetry_sdk::Resource,
    trace_id: TraceId,
    span_name: &'static str,
    span_kind: SpanKind,
    attributes: Vec<KeyValue>,
    parent_context: Option<opentelemetry::Context>,
    expected_decision: Option<SamplingDecision>,
}

fn create_benchmark_configs() -> Vec<BenchmarkConfig> {
    use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceState};

    let trace_id = TraceId::from(0x12345678901234567890123456789012_u128);

    // Helper to create parent context
    let create_parent_context = |is_sampled: bool| {
        let flags = if is_sampled {
            TraceFlags::SAMPLED
        } else {
            TraceFlags::default()
        };
        let span_context = SpanContext::new(
            trace_id,
            SpanId::from(0x1234567890123456_u64),
            flags,
            false,
            TraceState::default(),
        );
        opentelemetry::Context::current().with_remote_span_context(span_context)
    };

    vec![
        // 1. All spans rule (baseline)
        BenchmarkConfig {
            name: "rule_all_spans_only_rate",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: None,
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "something",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar"), KeyValue::new("bar", "baz")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 2. Service rule - matching
        BenchmarkConfig {
            name: "service_rule_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: Some("test-service".to_string()),
                name: None,
                resource: None,
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 3. Service rule - not matching
        BenchmarkConfig {
            name: "service_rule_not_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: Some("test-service".to_string()),
                name: None,
                resource: None,
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("other-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 4. Name pattern rule - matching
        BenchmarkConfig {
            name: "name_pattern_rule_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: Some("http.*".to_string()),
                resource: None,
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("http.method", "GET")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 5. Name pattern rule - not matching
        BenchmarkConfig {
            name: "name_pattern_rule_not_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: Some("http.*".to_string()),
                resource: None,
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "grpc.request",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("rpc.method", "GetUser")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 6. Resource pattern rule - matching
        BenchmarkConfig {
            name: "resource_pattern_rule_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: Some("/api/*".to_string()),
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("http.method", "GET"),
                KeyValue::new("http.route", "/api/users"),
            ],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 7. Resource pattern rule - not matching
        BenchmarkConfig {
            name: "resource_pattern_rule_not_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: Some("/api/*".to_string()),
                tags: HashMap::new(),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("http.method", "GET"),
                KeyValue::new("http.route", "/health"),
            ],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 8. Tag rule - matching
        BenchmarkConfig {
            name: "tag_rule_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: None,
                tags: HashMap::from([("environment".to_string(), "production".to_string())]),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "production"),
                KeyValue::new("foo", "bar"),
            ],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 9. Tag rule - not matching
        BenchmarkConfig {
            name: "tag_rule_not_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: None,
                tags: HashMap::from([("environment".to_string(), "production".to_string())]),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![
                KeyValue::new("environment", "staging"),
                KeyValue::new("foo", "bar"),
            ],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 10. Complex rule - matching
        BenchmarkConfig {
            name: "complex_rule_matching",
            rules: vec![SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("api-service".to_string()),
                name: Some("http.*".to_string()),
                resource: Some("/api/v1/*".to_string()),
                tags: HashMap::from([("environment".to_string(), "production".to_string())]),
                provenance: "".to_string(),
            }],
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
            parent_context: None,
            expected_decision: None, // Probabilistic sampling at 0.5 rate
        },
        // 11. Complex rule - partial match
        BenchmarkConfig {
            name: "complex_rule_partial_match",
            rules: vec![SamplingRuleConfig {
                sample_rate: 0.5,
                service: Some("api-service".to_string()),
                name: Some("http.*".to_string()),
                resource: Some("/api/v1/*".to_string()),
                tags: HashMap::from([("environment".to_string(), "production".to_string())]),
                provenance: "".to_string(),
            }],
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
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 12. Multiple rules - first match
        BenchmarkConfig {
            name: "multiple_rules_first_match",
            rules: vec![
                SamplingRuleConfig {
                    sample_rate: 0.1,
                    service: Some("api-service".to_string()),
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
                SamplingRuleConfig {
                    sample_rate: 0.5,
                    service: Some("web-service".to_string()),
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
                SamplingRuleConfig {
                    sample_rate: 1.0,
                    service: None,
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
            ],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("api-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            parent_context: None,
            expected_decision: None, // Probabilistic sampling at 0.1 rate
        },
        // 13. Multiple rules - last match
        BenchmarkConfig {
            name: "multiple_rules_last_match",
            rules: vec![
                SamplingRuleConfig {
                    sample_rate: 0.1,
                    service: Some("api-service".to_string()),
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
                SamplingRuleConfig {
                    sample_rate: 0.5,
                    service: Some("web-service".to_string()),
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
                SamplingRuleConfig {
                    sample_rate: 1.0,
                    service: None,
                    name: None,
                    resource: None,
                    tags: HashMap::new(),
                    provenance: "".to_string(),
                },
            ],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("other-service")
                .build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: vec![KeyValue::new("foo", "bar")],
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 14. Many attributes
        BenchmarkConfig {
            name: "many_attributes",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: None,
                name: None,
                resource: None,
                tags: HashMap::from([("key10".to_string(), "value10".to_string())]),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder_empty().build(),
            trace_id,
            span_name: "test-operation",
            span_kind: SpanKind::Server,
            attributes: (0..20)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            parent_context: None,
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 15. Parent sampled - short circuit with many attributes and complex rules
        BenchmarkConfig {
            name: "parent_sampled_short_circuit",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: Some("test-service".to_string()),
                name: Some("http.*".to_string()),
                resource: Some("/api/*".to_string()),
                tags: HashMap::from([
                    ("environment".to_string(), "production".to_string()),
                    ("region".to_string(), "us-east-1".to_string()),
                    ("version".to_string(), "v1.2.3".to_string()),
                ]),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: (0..50)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            parent_context: Some(create_parent_context(true)),
            expected_decision: Some(SamplingDecision::RecordAndSample),
        },
        // 16. Parent not sampled - short circuit with many attributes and complex rules
        BenchmarkConfig {
            name: "parent_not_sampled_short_circuit",
            rules: vec![SamplingRuleConfig {
                sample_rate: 1.0,
                service: Some("test-service".to_string()),
                name: Some("http.*".to_string()),
                resource: Some("/api/*".to_string()),
                tags: HashMap::from([
                    ("environment".to_string(), "production".to_string()),
                    ("region".to_string(), "us-east-1".to_string()),
                    ("version".to_string(), "v1.2.3".to_string()),
                ]),
                provenance: "".to_string(),
            }],
            resource: opentelemetry_sdk::Resource::builder()
                .with_service_name("test-service")
                .build(),
            trace_id,
            span_name: "http.request",
            span_kind: SpanKind::Server,
            attributes: (0..50)
                .map(|i| KeyValue::new(format!("key{}", i), format!("value{}", i)))
                .collect(),
            parent_context: Some(create_parent_context(false)),
            expected_decision: Some(SamplingDecision::RecordOnly),
        },
    ]
}

fn bench_otel_span_sampling<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let configs = create_benchmark_configs();
    let links: Vec<opentelemetry::trace::Link> = vec![];

    for config in configs {
        let test_resource = Arc::new(RwLock::new(config.resource));
        let test_config = Arc::new(
            Config::builder()
                .set_trace_rate_limit(-1)
                .set_trace_sampling_rules(config.rules)
                .build(),
        );
        let test_sampler = Sampler::new(test_config, test_resource.clone(), None);

        c.bench_function(
            &format!("otel_sample_span/{}/{}", config.name, M::name()),
            |b| {
                b.iter_batched(
                    || (),
                    |_| {
                        bench_sample(
                            &test_sampler,
                            config.parent_context.as_ref(),
                            config.trace_id,
                            config.span_name,
                            &config.span_kind,
                            &config.attributes,
                            &links,
                            &config.expected_decision,
                        );
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }
}

#[inline(never)]
fn bench_sample(
    sampler: &Sampler,
    parent_context: Option<&opentelemetry::Context>,
    trace_id: TraceId,
    span_name: &str,
    span_kind: &SpanKind,
    attributes: &[KeyValue],
    links: &[opentelemetry::trace::Link],
    expected_decision: &Option<SamplingDecision>,
) {
    let result = black_box(sampler).should_sample(
        black_box(parent_context),
        black_box(trace_id),
        black_box(span_name),
        black_box(span_kind),
        black_box(attributes),
        black_box(links),
    );
    if let Some(expected_decision) = expected_decision {
        assert_eq!(result.decision, *expected_decision);
        black_box(result);
    } else {
        black_box(result);
    }
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = bench_otel_span_sampling);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_otel_span_sampling);
criterion_main!(memory_benches, wall_time_benches);
