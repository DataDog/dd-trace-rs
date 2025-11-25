// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use datadog_opentelemetry::configuration::{Config, TracePropagationStyle};
use datadog_opentelemetry::core::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};

use datadog_opentelemetry::propagation::{carrier::Extractor, DatadogCompositePropagator};
use std::{collections::HashMap, sync::Arc};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

struct BenchExtractor {
    headers: HashMap<String, String>,
}

impl BenchExtractor {
    fn with_headers(headers: HashMap<String, String>) -> Self {
        Self { headers }
    }
}

impl Extractor for BenchExtractor {
    fn get(&self, key: &str) -> Option<&str> {
        let k = if key.chars().any(char::is_uppercase) {
            &key.to_lowercase()
        } else {
            key
        };
        self.headers.get(k).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(String::as_str).collect()
    }
}

fn create_simple_datadog_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "x-datadog-trace-id".to_string(),
        "1234567890123456789".to_string(),
    );
    headers.insert(
        "x-datadog-parent-id".to_string(),
        "9876543210987654321".to_string(),
    );
    headers.insert("x-datadog-sampling-priority".to_string(), "1".to_string());
    headers.insert("x-datadog-origin".to_string(), "synthetics".to_string());
    headers.insert(
        "x-datadog-tags".to_string(),
        "_dd.p.upstream_services=service1,_dd.p.dm=-1,user.id=12345".to_string(),
    );
    headers
}

fn create_complex_datadog_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "x-datadog-trace-id".to_string(),
        "1234567890123456789".to_string(),
    );
    headers.insert(
        "x-datadog-parent-id".to_string(),
        "9876543210987654321".to_string(),
    );
    headers.insert("x-datadog-sampling-priority".to_string(), "2".to_string());
    headers.insert("x-datadog-origin".to_string(), "lambda".to_string());

    // Build complex tags with many propagation tags
    let mut tags = Vec::new();
    tags.push("_dd.p.upstream_services=service1,service2,service3".to_string());
    tags.push("_dd.p.dm=-1".to_string());
    tags.push("_dd.p.tid=1234567890abcdef".to_string());

    // Add many custom propagation tags
    for i in 0..20 {
        tags.push(format!("_dd.p.custom_tag_{i}=value_with_some_content_{i}"));
    }

    headers.insert("x-datadog-tags".to_string(), tags.join(","));
    headers
}

fn create_simple_tracecontext_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "traceparent".to_string(),
        "00-1234567890abcdef1234567890abcdef-9876543210987654-01".to_string(),
    );
    headers.insert("tracestate".to_string(), "dd=s:1;o:synthetics;p:9876543210987654321;t._dd.p.upstream_services:service1;t.user.id:12345".to_string());
    headers
}

fn create_complex_tracecontext_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "traceparent".to_string(),
        "00-1234567890abcdef1234567890abcdef-9876543210987654-01".to_string(),
    );

    // Build complex tracestate with many values
    let mut tracestate_parts = Vec::new();
    tracestate_parts.push("s:2".to_string());
    tracestate_parts.push("o:lambda".to_string());
    tracestate_parts.push("p:9876543210987654321".to_string());

    // Add many propagation tags
    for i in 0..15 {
        tracestate_parts.push(format!("t._dd.p.custom_tag_{i}:value_with_content_{i}"));
    }

    headers.insert(
        "tracestate".to_string(),
        format!("dd={}", tracestate_parts.join(";")),
    );
    headers
}

fn create_both_propagation_headers() -> HashMap<String, String> {
    let mut headers = create_simple_datadog_headers();
    let tracecontext_headers = create_simple_tracecontext_headers();
    headers.extend(tracecontext_headers);
    headers
}

fn bench_datadog_only_extract<
    M: criterion::measurement::Measurement + MeasurementName + 'static,
>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder()
        .set_trace_propagation_style_extract(vec![TracePropagationStyle::Datadog])
        .build();
    let propagator = DatadogCompositePropagator::new(Arc::new(config));

    c.bench_function(&format!("extract_datadog_only_simple/{}", M::name()), |b| {
        b.iter_batched(
            || BenchExtractor::with_headers(create_simple_datadog_headers()),
            |carrier| black_box(propagator.extract(black_box(&carrier))),
            BatchSize::LargeInput,
        )
    });

    c.bench_function(
        &format!("extract_datadog_only_complex/{}", M::name()),
        |b| {
            b.iter_batched(
                || BenchExtractor::with_headers(create_complex_datadog_headers()),
                |carrier| black_box(propagator.extract(black_box(&carrier))),
                BatchSize::LargeInput,
            )
        },
    );
}

fn bench_tracecontext_only_extract<
    M: criterion::measurement::Measurement + MeasurementName + 'static,
>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder()
        .set_trace_propagation_style_extract(vec![TracePropagationStyle::TraceContext])
        .build();
    let propagator = DatadogCompositePropagator::new(Arc::new(config));

    c.bench_function(
        &format!("extract_tracecontext_only_simple/{}", M::name()),
        |b| {
            b.iter_batched(
                || BenchExtractor::with_headers(create_simple_tracecontext_headers()),
                |carrier| black_box(propagator.extract(black_box(&carrier))),
                BatchSize::LargeInput,
            )
        },
    );

    c.bench_function(
        &format!("extract_tracecontext_only_complex/{}", M::name()),
        |b| {
            b.iter_batched(
                || BenchExtractor::with_headers(create_complex_tracecontext_headers()),
                |carrier| black_box(propagator.extract(black_box(&carrier))),
                BatchSize::LargeInput,
            )
        },
    );
}

fn bench_both_propagation_extract<
    M: criterion::measurement::Measurement + MeasurementName + 'static,
>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder()
        .set_trace_propagation_style_extract(vec![
            TracePropagationStyle::Datadog,
            TracePropagationStyle::TraceContext,
        ])
        .build();
    let propagator = DatadogCompositePropagator::new(Arc::new(config));

    c.bench_function(&format!("extract_both_propagation/{}", M::name()), |b| {
        b.iter_batched(
            || BenchExtractor::with_headers(create_both_propagation_headers()),
            |carrier| black_box(propagator.extract(black_box(&carrier))),
            BatchSize::LargeInput,
        )
    });
}

criterion_group! {
    name = memory_benches;
    config = memory_allocated_measurement(&GLOBAL);
    targets = bench_datadog_only_extract,
              bench_tracecontext_only_extract,
              bench_both_propagation_extract
}

criterion_group! {
    name = wall_time_benches;
    config = Criterion::default();
    targets = bench_datadog_only_extract,
              bench_tracecontext_only_extract,
              bench_both_propagation_extract
}

criterion_main!(memory_benches, wall_time_benches);
