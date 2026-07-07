// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Memory allocation sampling.
//!
//! Opt in by declaring [`SampledAllocator`] as your process's
//! `#[global_allocator]`:
//!
//! ```no_run
//! use datadog_opentelemetry::memory_profiling::SampledAllocator;
//! use std::alloc::System;
//!
//! #[global_allocator]
//! static ALLOC: SampledAllocator<System> = SampledAllocator::<System>::DEFAULT;
//!
//! datadog_opentelemetry::memory_profiling().init();
//! ```
//!
//! This crate only emits sampled allocation events; it does not collect or
//! export them. Run an out-of-process profiler such as
//! [`dd-otel-host-profiler`](https://github.com/DataDog/dd-otel-host-profiler)
//! alongside the instrumented process to collect and ship samples to
//! Datadog.

pub use libdd_heap_allocator::SampledAllocator;

/// Builder for enabling memory allocation sampling.
pub struct DatadogMemoryProfilerBuilder {
    _private: (),
}

impl DatadogMemoryProfilerBuilder {
    /// Confirms the memory profiling opt-in.
    ///
    /// This has no effect unless [`SampledAllocator`] is declared as the
    /// process's `#[global_allocator]`; sampled allocations are picked up
    /// by an external profiler, not by this call.
    pub fn init(self) {}
}

/// Starts building a memory profiling configuration.
pub fn memory_profiling() -> DatadogMemoryProfilerBuilder {
    DatadogMemoryProfilerBuilder { _private: () }
}
