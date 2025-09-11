// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{alloc::GlobalAlloc, cell::Cell, hint::black_box, time::Duration};

// Copyright 2024-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

#[global_allocator]
static GLOBAL: ReportingAllocator<std::alloc::System> = ReportingAllocator::new(std::alloc::System);

trait MeasurementName {
    fn name() -> &'static str;
}

impl MeasurementName for criterion::measurement::WallTime {
    fn name() -> &'static str {
        "wall_time"
    }
}

fn bench_span_transformation<M: criterion::measurement::Measurement + MeasurementName + 'static>(
    c: &mut Criterion<M>,
) {
    let test_data: Vec<datadog_opentelemetry_mappings::transform_tests::Test> =
        datadog_opentelemetry_mappings::transform_tests::test_cases();
    for test in &test_data {
        let input_span = test.input_span.clone();
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
                        black_box(datadog_opentelemetry_mappings::otel_span_to_dd_span(
                            input_span,
                            &input_resource,
                        ));
                    },
                    criterion::BatchSize::LargeInput,
                )
            },
        );
    }
}

criterion_group!(name = memory_benches; config = memory_allocated_measurement(); targets = bench_span_transformation);
criterion_group!(name = wall_time_benches; config = Criterion::default(); targets = bench_span_transformation);
criterion_main!(memory_benches, wall_time_benches);

fn memory_allocated_measurement() -> Criterion<AllocatedBytesMeasurement> {
    Criterion::default()
        .with_measurement(AllocatedBytesMeasurement(Cell::new(false)))
        .measurement_time(Duration::from_millis(1))
        .warm_up_time(Duration::from_millis(1))
        .sample_size(10)
}

#[derive(Debug)]
struct AllocStats {
    allocated_bytes: usize,
    #[allow(dead_code)]
    allocations: usize,
}

struct ReportingAllocator<T: GlobalAlloc> {
    alloc: T,
    allocated_bytes: std::sync::atomic::AtomicUsize,
    allocations: std::sync::atomic::AtomicUsize,
}

impl<T: GlobalAlloc> ReportingAllocator<T> {
    pub const fn new(alloc: T) -> Self {
        Self {
            alloc,
            allocated_bytes: std::sync::atomic::AtomicUsize::new(0),
            allocations: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn stats(&self) -> AllocStats {
        AllocStats {
            allocated_bytes: self
                .allocated_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            allocations: self.allocations.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

unsafe impl<T: GlobalAlloc> GlobalAlloc for ReportingAllocator<T> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.allocated_bytes
            .fetch_add(layout.size(), std::sync::atomic::Ordering::Relaxed);
        self.allocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.alloc.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        self.alloc.dealloc(ptr, layout);
    }
}

struct AllocatedBytesMeasurement(Cell<bool>);

impl MeasurementName for AllocatedBytesMeasurement {
    fn name() -> &'static str {
        "allocated_bytes"
    }
}

impl criterion::measurement::Measurement for AllocatedBytesMeasurement {
    type Intermediate = usize;

    type Value = usize;

    fn start(&self) -> Self::Intermediate {
        GLOBAL.stats().allocated_bytes
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        GLOBAL.stats().allocated_bytes - i
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        let b = self.0.get();
        self.0.set(!b);
        // Criterion really doesn't like when all results have the same value, and since allocation
        // is deterministic, that tend to happen a lot...
        // We add a small +/- epsilon to have two measurements each time, without affecting the
        // overall distribution of values.
        *value as f64 + if b { 0.1 } else { -0.1 }
    }

    fn formatter(&self) -> &dyn criterion::measurement::ValueFormatter {
        &AllocationFormatter
    }
}

struct AllocationFormatter;

impl criterion::measurement::ValueFormatter for AllocationFormatter {
    fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
        let log_scale: f64 = typical_value.log10().round();
        if log_scale.is_infinite() || log_scale.is_nan() || log_scale < 0.0 {
            return "B";
        }
        let scale = (log_scale as i32 / 3).min(4);
        values.iter_mut().for_each(|v| {
            let scaled = *v
                / if scale == 0 {
                    1.0
                } else {
                    10_f64.powi(scale * 3)
                };
            assert!(
                !scaled.is_nan(),
                "Scaled value is NaN, original value: {}, scale: {}",
                *v,
                scale
            );
            *v = scaled;
        });
        match scale {
            0 => "b",
            1 => "Kb",
            2 => "Mb",
            3 => "Gb",
            _ => "Tb",
        }
    }

    fn scale_throughputs(
        &self,
        _typical_value: f64,
        throughput: &criterion::Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        match throughput {
            Throughput::Bytes(_) => "B/s",
            Throughput::BytesDecimal(_) => "B/s",
            Throughput::Elements(_) => "elements/s",
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "B"
    }
}
