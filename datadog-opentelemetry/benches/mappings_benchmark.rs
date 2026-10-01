// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;

// Copyright 2024-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::core_pub_hack::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::mappings::{transform_tests::test_span_to_sdk_span, DdSpan};

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

        // Reuse a single span across iterations, like the exporter's SpanPool does:
        // the conversion clears the span's collections and refills them, so their
        // capacity (and the span itself) is recycled instead of reallocated.
        let mut dd_span = DdSpan::default();

        c.bench_function(
            &format!("otel_span_to_dd_span/{}/{}", test.name, M::name()),
            |b| {
                b.iter(|| {
                    datadog_opentelemetry::mappings::otel_span_to_dd_span(
                        &mut dd_span,
                        &input_span,
                        &input_resource,
                    );
                    black_box(&dd_span);
                })
            },
        );
    }
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = bench_span_transformation);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_span_transformation);
criterion_main!(memory_benches, wall_time_benches);
