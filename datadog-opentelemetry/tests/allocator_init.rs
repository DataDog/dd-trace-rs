// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Regression test for GitHub issue #346: the tracer's load-time lineage
//! constructor must not allocate through the Rust global allocator.
//! Hosts that load the tracer as a shared library
//! may only wire their `#[global_allocator]` up once `dlopen` returns, but
//! `dlopen` already runs the library's constructors — any allocation there
//! aborts the host process, and a `GlobalAlloc` cannot unwind, so not even
//! `catch_unwind` can save it.
//!
//! This binary installs a recording `#[global_allocator]`: every allocation
//! before the test body runs (the constructor's window) captures a
//! backtrace, and none may contain `datadog_opentelemetry` frames. std
//! itself allocates before `main`, hence the frame filter.

// The env read is deliberate: the lineage variable is process metadata,
// not tracer configuration.
#![allow(clippy::disallowed_methods)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::backtrace::Backtrace;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const ENV_PARENT: &str = "_DD_PARENT_RS_SESSION_ID";

/// Flipped when the test body starts: everything before it is the
/// "before main" window (binary startup, the lineage constructor, std's
/// runtime init, the test harness).
static REACHED_TEST: AtomicBool = AtomicBool::new(false);

/// Recording a backtrace allocates; this guard prevents recursion.
static RECORDING: AtomicBool = AtomicBool::new(false);

static PRE_MAIN_ALLOCATIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct RecordingAlloc;

unsafe impl GlobalAlloc for RecordingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !REACHED_TEST.load(Ordering::SeqCst) && !RECORDING.swap(true, Ordering::SeqCst) {
            let record = format!(
                "allocation of {} bytes before main:\n{}",
                layout.size(),
                Backtrace::force_capture()
            );
            PRE_MAIN_ALLOCATIONS.lock().unwrap().push(record);
            RECORDING.store(false, Ordering::SeqCst);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: RecordingAlloc = RecordingAlloc;

#[cfg_attr(miri, ignore)]
#[test]
fn lineage_ctor_does_not_allocate_before_main() {
    REACHED_TEST.store(true, Ordering::SeqCst);

    // Reference the tracer so its constructor is linked into this binary;
    // the env var then proves the constructor ran, so the assertions below
    // cannot pass vacuously.
    let _ = datadog_opentelemetry::tracing();
    let parent = std::env::var(ENV_PARENT)
        .expect("the tracer's load-time lineage constructor did not run in this binary");
    assert!(
        uuid::Uuid::parse_str(&parent).is_ok(),
        "runtime id is a UUID"
    );

    let records = PRE_MAIN_ALLOCATIONS.lock().unwrap();
    for record in records.iter() {
        assert!(
            !record.contains("datadog_opentelemetry"),
            "the tracer allocated before `main`:\n{record}"
        );
    }
}
