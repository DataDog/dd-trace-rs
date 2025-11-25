// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use datadog_opentelemetry::configuration::{Config, TracePropagationStyle};
use datadog_opentelemetry::core::{
    sampling::{mechanism, priority},
    test_utils::benchmarks::{memory_allocated_measurement, MeasurementName, ReportingAllocator},
};
use datadog_opentelemetry::propagation::{
    carrier::Injector,
    context::{InjectSpanContext, Sampling, SpanContext},
    DatadogCompositePropagator,
};
use std::{collections::HashMap, sync::Arc};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

fn span_context_to_inject(c: &mut SpanContext) -> InjectSpanContext<'_> {
    InjectSpanContext {
        trace_id: c.trace_id,
        span_id: c.span_id,
        sampling: c.sampling,
        origin: c.origin.as_deref(),
        tags: &mut c.tags,
        is_remote: c.is_remote,
        tracestate: None,
    }
}

// Mock injector for benchmarking
struct BenchInjector {
    headers: HashMap<String, String>,
}

impl BenchInjector {
    fn new() -> Self {
        Self {
            headers: HashMap::with_capacity(10),
        }
    }
}

impl Injector for BenchInjector {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(key.to_string(), value);
    }
}

fn create_simple_span_context() -> SpanContext {
    SpanContext {
        trace_id: 0x1234567890abcdef1234567890abcdef,
        span_id: 0x1234567890abcdef,
        sampling: Sampling {
            priority: Some(priority::USER_KEEP),
            mechanism: Some(mechanism::MANUAL),
        },
        origin: Some("synthetics".to_string()),
        tags: {
            let mut tags = HashMap::new();
            tags.insert(
                "_dd.p.upstream_services".to_string(),
                "service1".to_string(),
            );
            tags.insert("_dd.p.dm".to_string(), "-1".to_string());
            tags.insert("user.id".to_string(), "12345".to_string());
            tags
        },
        tracestate: None,
        is_remote: false,
        links: Vec::new(),
    }
}

fn create_complex_span_context() -> SpanContext {
    let mut context = create_simple_span_context();

    // Add many propagation tags to stress test
    for i in 0..20 {
        context.tags.insert(
            format!("_dd.p.custom_tag_{i}"),
            format!("value_with_some_content_{i}"),
        );
    }

    // Add regular tags that shouldn't be propagated
    for i in 0..10 {
        context
            .tags
            .insert(format!("regular_tag_{i}"), format!("value_{i}"));
    }

    context.origin = Some("lambda".to_string());
    context
}

fn bench_datadog_only_inject<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder()
        .set_trace_propagation_style_inject(vec![TracePropagationStyle::Datadog])
        .set_datadog_tags_max_length_with_no_limit(20000)
        .build();
    let propagator = DatadogCompositePropagator::new(Arc::new(config));

    c.bench_function(&format!("inject_datadog_only_simple/{}", M::name()), |b| {
        b.iter_batched(
            || (create_simple_span_context(), BenchInjector::new()),
            |(mut context, mut carrier)| {
                propagator.inject(&mut span_context_to_inject(&mut context), &mut carrier)
            },
            BatchSize::LargeInput,
        )
    });

    c.bench_function(&format!("inject_datadog_only_complex/{}", M::name()), |b| {
        b.iter_batched(
            || (create_complex_span_context(), BenchInjector::new()),
            |(mut context, mut carrier)| {
                propagator.inject(&mut span_context_to_inject(&mut context), &mut carrier)
            },
            BatchSize::LargeInput,
        )
    });
}

fn bench_tracecontext_only_inject<
    M: criterion::measurement::Measurement + MeasurementName + 'static,
>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder()
        .set_trace_propagation_style_inject(vec![TracePropagationStyle::TraceContext])
        .build();
    let propagator = DatadogCompositePropagator::new(Arc::new(config));

    c.bench_function(
        &format!("inject_tracecontext_only_simple/{}", M::name()),
        |b| {
            b.iter_batched(
                || (create_simple_span_context(), BenchInjector::new()),
                |(mut context, mut carrier)| {
                    propagator.inject(&mut span_context_to_inject(&mut context), &mut carrier)
                },
                BatchSize::LargeInput,
            )
        },
    );

    c.bench_function(
        &format!("inject_tracecontext_only_complex/{}", M::name()),
        |b| {
            b.iter_batched(
                || (create_complex_span_context(), BenchInjector::new()),
                |(mut context, mut carrier)| {
                    propagator.inject(&mut span_context_to_inject(&mut context), &mut carrier)
                },
                BatchSize::LargeInput,
            )
        },
    );
}

criterion_group! {
    name = memory_benches;
    config = memory_allocated_measurement(&GLOBAL);
    targets = bench_datadog_only_inject,
             bench_tracecontext_only_inject
}

criterion_group! {
    name = wall_time_benches;
    config = Criterion::default();
    targets = bench_datadog_only_inject,
            bench_tracecontext_only_inject
}

criterion_main!(memory_benches, wall_time_benches);
