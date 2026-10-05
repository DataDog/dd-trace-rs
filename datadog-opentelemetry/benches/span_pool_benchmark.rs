// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Measures the impact of the [`SpanPool`] on otel→datadog span conversion.
//!
//! Each iteration of the `pooled` variant runs the exporter's full recycle cycle:
//! a recycled span is taken from the pool, converted in place, and the chunk is
//! handed back to the pool (spans are reset there, keeping their collections'
//! capacity). The `unpooled` variant converts into a freshly allocated span that
//! is dropped normally, i.e. the behavior without a pool.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::core_pub_hack::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::mappings::{
    otel_span_to_dd_span, transform_tests::test_span_to_sdk_span, DdSpan, SpanStr,
};
use libdd_trace_utils::span::span_pool::SpanPool;

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

fn bench_span_pool<M: criterion::measurement::Measurement + MeasurementName + 'static>(
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

        // Pooled: recycled span, converted in place and returned to the pool.
        {
            let pool: SpanPool<SpanStr<'static>> = SpanPool::with_capacity(1_000);
            c.bench_function(&format!("span_pool/pooled/{}", test.name), |b| {
                b.iter(|| {
                    // SAFETY: the pool is typed `SpanStr<'static>` but the spans it
                    // hands out borrow from `input_span`/`input_resource` for the
                    // duration of this iteration; returning them to the pool resets
                    // them (dropping those borrows) before the borrow sources can
                    // go away. This mirrors the lifetime erasure done in the span
                    // exporter.
                    let pool: &SpanPool<SpanStr> = unsafe { std::mem::transmute(&pool) };
                    let mut dd_span = pool.get_span();
                    otel_span_to_dd_span(&mut dd_span, &input_span, &input_resource);
                    black_box(&dd_span);
                    // Return the span to the pool, as dropping the exporter's
                    // PooledChunks does, going through a recycled chunk buffer.
                    let mut chunk = pool.pull_empty_chunk();
                    chunk.push(dd_span);
                    pool.add_chunks(std::iter::once(chunk));
                })
            });
        }

        // Unpooled: fresh span allocation each iteration, dropped normally.
        c.bench_function(&format!("span_pool/unpooled/{}", test.name), |b| {
            b.iter(|| {
                let mut dd_span = DdSpan::default();
                otel_span_to_dd_span(&mut dd_span, &input_span, &input_resource);
                black_box(&dd_span);
            })
        });
    }
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = bench_span_pool);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_span_pool);
criterion_main!(memory_benches, wall_time_benches);
