// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Simple Tokio Timeline Example
//!
//! Minimal example showing how to set up Tokio timeline telemetry with Datadog.
//! This spawns a few async tasks and uploads timeline data to Datadog's profiling API.
//!
//! # Requirements
//!
//! Requires Tokio's unstable APIs:
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline --bin simple
//! ```
//!
//! # Environment Variables
//!
//! - `DD_SERVICE`: Service name (default: "tokio-timeline-simple")
//! - `DD_ENV`: Environment (default: "development")
//! - `DD_AGENT_HOST`: Datadog agent host (default: "localhost")
//! - `DD_TRACE_AGENT_PORT`: Agent port (default: 8126)

use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig};
use dial9_tokio_telemetry::telemetry::TracedRuntime;

fn main() {
    // Configure Datadog connection
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service(
            std::env::var("DD_SERVICE").unwrap_or_else(|_| "tokio-timeline-simple".to_string()),
        )
        .set_env(std::env::var("DD_ENV").unwrap_or_else(|_| "development".to_string()))
        .set_version("0.1.0".to_string())
        .build();

    // Configure timeline uploads
    let timeline_config = TimelineConfig::builder()
        .upload_interval(Duration::from_secs(10))
        .max_buffered_events(10_000)
        .build();

    // Build the timeline writer that sends data to Datadog
    let (writer, timeline_handle) = timeline()
        .with_config(datadog_config)
        .with_timeline_config(timeline_config)
        .with_channel_capacity(1_000)
        .build_writer()
        .expect("failed to build timeline writer");

    // Create a traced Tokio runtime
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.worker_threads(2).enable_all();

    let (runtime, guard) = TracedRuntime::builder()
        .with_task_tracking(true)
        .build_and_start(runtime_builder, Box::new(writer))
        .expect("failed to build traced runtime");

    let handle = guard.handle();

    // Run some async work
    runtime.block_on(async {
        println!("Starting simple timeline demo...\n");

        // Spawn tasks that do a mix of CPU work and I/O
        let mut tasks = Vec::new();
        for i in 0..5 {
            let task = handle.spawn(async move {
                println!("Task {} starting", i);

                // CPU-bound work with yields - this should generate poll events
                for round in 0..10 {
                    // Do some computation
                    let mut sum = 0u64;
                    for j in 0..10000 {
                        sum = sum.wrapping_add(j * (i as u64 + 1));
                    }
                    // Yield to let other tasks run and generate poll events
                    tokio::task::yield_now().await;

                    if round % 3 == 0 {
                        // Occasional I/O simulation
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }

                    // Prevent optimization
                    std::hint::black_box(sum);
                }

                println!("Task {} done", i);
            });
            tasks.push(task);
        }

        // Wait for all tasks
        for task in tasks {
            task.await.ok();
        }

        println!("\nAll tasks completed!");
    });

    // Shutdown sequence is critical for event delivery:
    // 1. Drop runtime first - this makes worker threads exit, flushing their buffers
    // 2. Drop dial9 guard - this triggers final flush from collector to our writer
    // 3. Then flush our timeline
    println!("Shutting down...");

    // Drop runtime to trigger worker thread exit and buffer flush
    drop(runtime);

    // Now drop the guard - this flushes collector to our TraceWriter
    drop(guard);

    // Give dial9 events time to reach our worker
    std::thread::sleep(Duration::from_millis(100));

    // Final flush of our timeline
    timeline_handle.flush();
    std::thread::sleep(Duration::from_millis(500));

    timeline_handle.shutdown(Duration::from_secs(5)).ok();
    println!("Done!");
}
