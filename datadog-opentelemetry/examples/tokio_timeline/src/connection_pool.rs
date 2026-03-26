// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Connection Pool Example
//!
//! Demonstrates semaphore-limited concurrency, simulating a connection pool.
//! The timeline will show tasks waiting for pool slots and the pool utilization.
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline --bin connection_pool
//! ```

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig};
use dial9_tokio_telemetry::telemetry::TracedRuntime;
use tokio::sync::Semaphore;

fn main() {
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service("tokio-timeline-pool".to_string())
        .set_env("development".to_string())
        .build();

    let timeline_config = TimelineConfig::builder()
        .upload_interval(Duration::from_secs(10))
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
        println!("=== Connection Pool Pattern ===\n");
        println!("Pool size: 3 connections");
        println!("Requests: 20 concurrent\n");

        // Simulate a connection pool with limited slots
        let pool = Arc::new(Semaphore::new(3));
        let mut tasks = Vec::new();

        // Many tasks competing for few pool slots
        for task_id in 0..20 {
            let pool = Arc::clone(&pool);
            let task = handle.spawn(async move {
                // Wait for a pool slot
                let _permit = pool.acquire().await.unwrap();

                println!("[Request {}] Acquired connection", task_id);

                // Simulate database query with variable latency
                let query_time = 50 + (task_id % 5) * 20;
                tokio::time::sleep(Duration::from_millis(query_time as u64)).await;

                println!("[Request {}] Released after {}ms", task_id, query_time);
                // permit dropped here, releasing the slot
            });
            tasks.push(task);
        }

        for task in tasks {
            task.await.ok();
        }

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
