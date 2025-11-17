// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub mod benchmarks {
    //! Scaffolding for memory usage benchmarks
    //!
    //! See datadog_opentelemetry/benches/smoke.rs for usage

    use std::{
        alloc::{GlobalAlloc, System},
        cell::Cell,
        time::Duration,
    };

    use criterion::{Criterion, Throughput};

    pub trait MeasurementName {
        fn name() -> &'static str;
    }

    impl MeasurementName for criterion::measurement::WallTime {
        fn name() -> &'static str {
            "wall_time"
        }
    }

    pub fn memory_allocated_measurement(
        global_alloc: &'static ReportingAllocator<System>,
    ) -> Criterion<AllocatedBytesMeasurement<System>> {
        Criterion::default()
            .with_measurement(AllocatedBytesMeasurement(Cell::new(false), global_alloc))
            .measurement_time(Duration::from_millis(1))
            .warm_up_time(Duration::from_millis(1))
            .without_plots()
            .plotting_backend(criterion::PlottingBackend::None)
            .sample_size(10)
    }

    #[derive(Debug)]
    struct AllocStats {
        allocated_bytes: usize,
        #[allow(dead_code)]
        allocations: usize,
    }

    pub struct ReportingAllocator<T: GlobalAlloc> {
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

        fn stats(&self) -> AllocStats {
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

    pub struct AllocatedBytesMeasurement<T: GlobalAlloc + 'static>(
        Cell<bool>,
        &'static ReportingAllocator<T>,
    );

    impl<T: GlobalAlloc> MeasurementName for AllocatedBytesMeasurement<T> {
        fn name() -> &'static str {
            "allocated_bytes"
        }
    }

    impl<T: GlobalAlloc> criterion::measurement::Measurement for AllocatedBytesMeasurement<T> {
        type Intermediate = usize;

        type Value = usize;

        fn start(&self) -> Self::Intermediate {
            self.1.stats().allocated_bytes
        }

        fn end(&self, i: Self::Intermediate) -> Self::Value {
            self.1.stats().allocated_bytes - i
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
            // Criterion really doesn't like when all results have the same value, and since
            // allocation is deterministic, that tend to happen a lot...
            // We add a small +/- epsilon to have two measurements each time, without affecting the
            // overall distribution of values.
            *value as f64 + if b { 0.01 } else { -0.01 }
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
                return "b";
            }
            let scale = (log_scale as i32 / 3).min(4);
            values.iter_mut().for_each(|v| *v /= 10_f64.powi(scale * 3));
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
            "b"
        }
    }
}
