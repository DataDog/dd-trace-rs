// Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    hint::black_box,
    time::{Duration, SystemTime},
};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use datadog_opentelemetry::bench_support::{ChunkConverter, DdTracePool, Recycling};
use datadog_opentelemetry::configuration::Config;
use datadog_opentelemetry::core_pub_hack::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use opentelemetry::{
    trace::{SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId},
    InstrumentationScope, KeyValue,
};
use opentelemetry_sdk::{
    trace::{SpanData, SpanEvents, SpanLinks},
    Resource,
};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

/// Configurations exercised by the benchmarks: `(number of chunks, spans per chunk)`.
/// The small one resembles a single trace flush; the large one resembles a full payload.
const CONFIGS: &[(usize, usize)] = &[(1, 10), (20, 100)];

/// Large enough to hold a full iteration's worth of recycled spans and chunks.
const POOL_CAPACITY: usize = 4_096;

fn span_data(trace_idx: usize, span_idx: usize) -> SpanData {
    let start_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    SpanData {
        span_context: SpanContext::new(
            TraceId::from((trace_idx as u128 + 1) << 64 | 1),
            SpanId::from(span_idx as u64 + 1),
            TraceFlags::SAMPLED,
            false,
            Default::default(),
        ),
        parent_span_id: if span_idx == 0 {
            SpanId::INVALID
        } else {
            SpanId::from(span_idx as u64)
        },
        span_kind: if span_idx == 0 {
            SpanKind::Server
        } else {
            SpanKind::Client
        },
        name: Cow::Borrowed("GET /api/resource"),
        start_time,
        end_time: start_time + Duration::from_micros(500),
        attributes: vec![
            KeyValue::new("http.request.method", "GET"),
            KeyValue::new("http.route", "/api/resource/:id"),
            KeyValue::new("http.response.status_code", 200),
            KeyValue::new("url.path", "/api/resource/42"),
            KeyValue::new("server.address", "example.com"),
            KeyValue::new("network.protocol.version", "1.1"),
            KeyValue::new("user_agent.original", "bench"),
            KeyValue::new("thread.id", 7),
            KeyValue::new("code.line.number", 120),
            KeyValue::new("_sampling_priority_v1", 1),
            KeyValue::new("_dd.p.dm", "-0"),
        ],
        dropped_attributes_count: 0,
        events: SpanEvents::default(),
        links: SpanLinks::default(),
        status: Status::Unset,
        instrumentation_scope: InstrumentationScope::builder("bench").build(),
        parent_span_is_remote: false,
    }
}

fn input_chunks(num_chunks: usize, spans_per_chunk: usize) -> Vec<Vec<SpanData>> {
    (0..num_chunks)
        .map(|c| (0..spans_per_chunk).map(|s| span_data(c, s)).collect())
        .collect()
}

fn bench_export_conversion<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let config = Config::builder().build();
    let converter = ChunkConverter::new(&config);
    let resource = Resource::builder_empty()
        .with_attributes([
            KeyValue::new("service.name", "bench-service"),
            KeyValue::new("service.version", "1.2.3"),
            KeyValue::new("deployment.environment.name", "bench"),
        ])
        .build();

    let mut group = c.benchmark_group(format!("export_conversion/{}", M::name()));
    for &(num_chunks, spans_per_chunk) in CONFIGS {
        let chunks = input_chunks(num_chunks, spans_per_chunk);
        group.throughput(Throughput::Elements((num_chunks * spans_per_chunk) as u64));
        for (name, recycling) in [
            ("allocating", Recycling::None),
            ("pooled", Recycling::Returned),
            ("pooled_consumed", Recycling::Consumed),
        ] {
            let pool = DdTracePool::with_capacity(POOL_CAPACITY);
            // Warm the pool so that measured iterations run in steady state.
            converter.convert(&chunks, &resource, &pool, Recycling::Returned);
            group.bench_function(format!("{num_chunks}x{spans_per_chunk}/{name}"), |b| {
                b.iter(|| {
                    black_box(converter.convert(black_box(&chunks), &resource, &pool, recycling))
                })
            });
        }
    }
    group.finish();
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = bench_export_conversion);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_export_conversion);
criterion_main!(memory_benches, wall_time_benches);
