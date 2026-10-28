// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;

// Copyright 2024-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0
use bumpalo::Bump;
use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::core_pub_hack::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::mappings::transform_tests::test_span_to_sdk_span;
use datadog_opentelemetry::mappings::SpanStr;
use libdd_trace_utils::span::v1::span_pool::SpanPoolV1;

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

fn bench_span_transformation<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let test_data: Vec<datadog_opentelemetry::mappings::transform_tests::Test> =
        datadog_opentelemetry::mappings::transform_tests::test_cases();
    for test in &test_data {
        let input_span = test_span_to_sdk_span(&test.input_span);
        let input_resource = opentelemetry_sdk::Resource::builder_empty()
            .with_attributes(
                test.input_resource
                    .iter()
                    .map(|(k, v)| opentelemetry::KeyValue::new(*k, *v)),
            )
            .build();

        let pool: SpanPoolV1<SpanStr<'static>> = SpanPoolV1::with_capacity(1_000);
        // Reuse a single arena across iterations, resetting it between spans.
        // This mirrors the exporter, which creates one arena per flush batch and
        // amortizes it over all spans in the batch, instead of paying a fresh arena
        // (and a global-allocator chunk) per span.
        let mut arena = Bump::new();

        c.bench_function(
            &format!("otel_span_to_dd_span/{}/{}", test.name, M::name()),
            |b| {
                b.iter_batched(
                    || input_span.clone(),
                    |input_span| {
                        arena.reset();
                        // SAFETY: the pool is typed `SpanStr<'static>` but the spans it
                        // hands out borrow from `input_span`/`input_resource`/`arena` for
                        // the duration of this iteration; returning them to the pool
                        // resets them (dropping those borrows) before the borrow sources
                        // can go away. This mirrors the lifetime erasure done in the span
                        // exporter.
                        let pool: &SpanPoolV1<SpanStr> = unsafe { std::mem::transmute(&pool) };
                        let dd_span = datadog_opentelemetry::mappings::otel_span_to_dd_span_into(
                            pool.get_span(),
                            &input_span,
                            &input_resource,
                            &arena,
                        );
                        black_box(&dd_span);
                        // Return the span to the pool, as dropping the exporter's
                        // PooledTraceChunks does, going through a recycled chunk buffer.
                        let mut chunk = pool.get_chunk();
                        chunk.spans.push(dd_span);
                        pool.add_chunks(std::iter::once(chunk));
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = bench_span_transformation);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_span_transformation);
criterion_main!(memory_benches, wall_time_benches);
