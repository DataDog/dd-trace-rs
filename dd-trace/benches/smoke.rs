// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{alloc::System, hint::black_box, thread, time::Duration};

use criterion::{
    criterion_group, criterion_main, measurement::Measurement, Criterion, PlottingBackend,
};
use dd_trace::test_utils::benchmarks::{
    memory_allocated_measurement, MeasurementName, ReportingAllocator,
};

#[global_allocator]
static GLOBAL: ReportingAllocator<System> = ReportingAllocator::new(System);

fn benchmark<M: Measurement + MeasurementName + 'static>(c: &mut Criterion<M>) {
    c.bench_function(&format!("sleep/{}", M::name()), |b| {
        b.iter(|| {
            thread::sleep(Duration::from_nanos(10));
        })
    });

    c.bench_function(&format!("allocate/{}", M::name()), |b| {
        b.iter(|| black_box(Box::new(101_u64)))
    });
}

criterion_group!(
    name = wall_time_benches;
    // Run for only a short time since this benchmark is useless
    config = Criterion::default()
        .measurement_time(Duration::from_millis(1))
        .warm_up_time(Duration::from_millis(1))
        .sample_size(10)
        .plotting_backend(PlottingBackend::None);
    targets = benchmark
);
criterion_group!(name = memory_benches; config = memory_allocated_measurement(&GLOBAL); targets = benchmark);
criterion_main!(wall_time_benches, memory_benches);
