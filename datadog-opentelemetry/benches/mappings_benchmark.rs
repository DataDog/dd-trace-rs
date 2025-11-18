// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::hint::black_box;

// Copyright 2024-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion};
use datadog_opentelemetry::core::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};
use datadog_opentelemetry::mappings::transform_tests::test_span_to_sdk_span;

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

        c.bench_function(
            &format!("otel_span_to_dd_span/{}/{}", test.name, M::name()),
            |b| {
                b.iter_batched(
                    || input_span.clone(),
                    |input_span| {
                        black_box(datadog_opentelemetry::mappings::otel_span_to_dd_span(
                            &input_span,
                            &input_resource,
                        ));
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
