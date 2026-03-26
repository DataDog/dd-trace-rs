// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Mutex Contention Example
//!
//! Demonstrates tasks competing for a shared resource. The timeline will show
//! tasks waiting/blocking on the mutex and the handoff patterns.
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline --bin mutex_contention
//! ```

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig, TimelineFormat};
use dial9_tokio_telemetry::telemetry::TracedRuntime;
use tokio::sync::Mutex;

fn main() {
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service("tokio-timeline-mutex".to_string())
        .set_env("development".to_string())
        .build();

    let timeline_config = TimelineConfig::builder()
        .upload_interval(Duration::from_secs(10))
        .format(TimelineFormat::GoTrace)
        .build();

    let (writer, timeline_handle) = timeline()
        .with_config(datadog_config)
        .with_timeline_config(timeline_config)
        .build_writer()
        .expect("failed to build timeline writer");

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.worker_threads(4).enable_all();

    let (runtime, guard) = TracedRuntime::builder()
        .with_task_tracking(true)
        .build_and_start(runtime_builder, Box::new(writer))
        .expect("failed to build traced runtime");

    let handle = guard.handle();

    runtime.block_on(async {
        println!("=== Mutex Contention Pattern ===\n");

        let counter = Arc::new(Mutex::new(0i32));
        let mut tasks = Vec::new();

        // Spawn many tasks that all try to increment the counter
        for task_id in 0..8 {
            let counter = Arc::clone(&counter);
            let task = handle.spawn(async move {
                for iteration in 0..10 {
                    // Acquire lock - will contend with other tasks
                    let mut guard = counter.lock().await;
                    *guard += 1;

                    // Hold lock while "processing" - increases contention
                    tokio::time::sleep(Duration::from_millis(15)).await;

                    let current = *guard;
                    drop(guard);

                    if iteration == 0 || iteration == 9 {
                        println!("[Task {}] iteration {}, counter = {}", task_id, iteration, current);
                    }

                    // Work outside the lock
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.ok();
        }

        let final_count = *counter.lock().await;
        println!("\nFinal count: {} (expected: 80)", final_count);
        println!("\n=== Done! ===");
    });

    // Shutdown sequence is CRITICAL for event delivery!
    // dial9 uses thread-local buffers (1024 event threshold) that only flush when:
    // - Buffer fills up (1024 events)
    // - Worker thread exits (Drop impl)
    // - Explicit flush
    //
    // ORDER MATTERS:
    // 1. Drop runtime first - worker threads exit, flushing thread-local buffers
    // 2. Drop dial9 guard - triggers final flush from collector to our writer
    // 3. Then flush our timeline
    println!("Shutting down...");

    drop(runtime);
    drop(guard);

    std::thread::sleep(Duration::from_millis(100));
    timeline_handle.flush();
    std::thread::sleep(Duration::from_millis(500));
    timeline_handle.shutdown(Duration::from_secs(5)).ok();
    println!("Done!");
}
