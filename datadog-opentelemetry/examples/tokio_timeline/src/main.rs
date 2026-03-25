// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Tokio Timeline Example
//!
//! This example demonstrates how to use the `tokio-timeline` feature in datadog-opentelemetry
//! to capture Tokio runtime events and upload them to Datadog for visualization in the
//! Timeline View.
//!
//! # Requirements
//!
//! This feature requires **Tokio's unstable APIs**. You must compile with the `tokio_unstable`
//! cfg flag:
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline
//! ```
//!
//! Alternatively, add the following to `.cargo/config.toml`:
//!
//! ```toml
//! [build]
//! rustflags = ["--cfg", "tokio_unstable"]
//! ```
//!
//! # What This Example Does
//!
//! 1. Creates a `TimelineConfig` to configure collection parameters
//! 2. Builds a `DatadogTimelineWriter` and `TimelineHandle` using the builder pattern
//! 3. Wraps a Tokio runtime with `dial9_tokio_telemetry::TracedRuntime` to capture events
//! 4. Runs some async workloads to generate telemetry
//! 5. Performs graceful shutdown to flush remaining events

use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig, TimelineFormat};
use dial9_tokio_telemetry::telemetry::TracedRuntime;

fn main() {
    // Step 1: Configure the Datadog service configuration
    //
    // This sets basic metadata that will be attached to the timeline data.
    // The configuration can also be loaded from environment variables
    // (DD_SERVICE, DD_ENV, DD_VERSION).
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service("tokio-timeline-example".to_string())
        .set_env("development".to_string())
        .set_version("0.1.0".to_string())
        .build();

    // Step 2: Configure timeline-specific settings
    //
    // - `upload_interval`: How often to upload data to Datadog (default: 60s)
    // - `max_buffer_size`: Maximum bytes to buffer before forcing a flush (default: 10MB)
    // - `max_buffered_events`: Maximum events to buffer before forcing a flush (default: 100k)
    // - `format`: Output format - GoTrace (default), Pprof, or Both
    let timeline_config = TimelineConfig::builder()
        .upload_interval(Duration::from_secs(5)) // Upload every 5 seconds for testing
        .max_buffered_events(50_000)
        .format(TimelineFormat::GoTrace) // Use Go trace format for timeline visualization
        .build();

    // Step 3: Build the timeline writer and handle
    //
    // The `timeline()` function returns a builder that creates:
    // - `DatadogTimelineWriter`: Implements `dial9_tokio_telemetry::TraceWriter` trait
    // - `TimelineHandle`: Used for flushing and graceful shutdown
    let (writer, timeline_handle) = timeline()
        .with_config(datadog_config)
        .with_timeline_config(timeline_config)
        .with_channel_capacity(10_000) // Optional: customize event channel size
        .build_writer()
        .expect("failed to build timeline writer");

    // Step 4: Create a traced Tokio runtime
    //
    // `TracedRuntime::build_and_start` wraps a Tokio runtime builder and the writer.
    // It captures runtime events like task spawns, polls, worker park/unpark, etc.
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.worker_threads(4).enable_all();

    let (runtime, guard) = TracedRuntime::build_and_start(runtime_builder, Box::new(writer))
        .expect("failed to build traced runtime");

    // Get a handle for spawning traced tasks
    // Using `handle.spawn()` instead of `tokio::spawn()` captures wake events,
    // which enables scheduler delay analysis in the Datadog Timeline View.
    let handle = guard.handle();

    // Step 5: Run your application logic
    //
    // Use the traced runtime to spawn and run async tasks.
    // All runtime events will be captured and sent to Datadog.
    //
    // Note: Using `handle.spawn()` (from the telemetry guard) instead of
    // `tokio::spawn()` captures wake events, enabling scheduler delay analysis.
    runtime.block_on(async {
        println!("Starting example workload...");

        // Spawn multiple tasks to generate interesting timeline data
        // Using handle.spawn() for wake event tracking
        // Generate enough events to trigger buffer flush (1024 per thread)
        let mut task_handles = Vec::new();

        for i in 0..50 {
            let task_handle = handle.spawn(async move {
                // Simulate some async work with many polls
                for j in 0..50 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    tokio::task::yield_now().await;
                    if j % 10 == 0 {
                        println!("Task {} completed iteration {}", i, j);
                    }
                }
            });
            task_handles.push(task_handle);
        }

        // Spawn some nested tasks
        let handle_clone = handle.clone();
        let nested_handle = handle.spawn(async move {
            let inner = handle_clone.spawn(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                println!("Inner nested task completed");
            });
            inner.await.expect("inner task failed");
            println!("Outer nested task completed");
        });
        task_handles.push(nested_handle);

        // Wait for all tasks to complete
        for task_handle in task_handles {
            task_handle.await.expect("task failed");
        }

        println!("All tasks completed!");
    });

    // Step 6: Graceful shutdown
    //
    // IMPORTANT: Use dial9's graceful_shutdown to flush all buffered events
    // before shutting down our timeline worker.
    println!("Shutting down...");

    // Use graceful_shutdown to flush dial9's buffered events (this is async)
    println!("Flushing dial9 telemetry...");
    runtime.block_on(async {
        if let Err(e) = guard.graceful_shutdown(Duration::from_secs(5)).await {
            eprintln!("dial9 graceful shutdown error: {}", e);
        }
    });
    println!("dial9 telemetry flushed");

    // Drop the runtime
    drop(runtime);
    println!("Runtime dropped");

    // Give our worker time to process the flushed events
    println!("Waiting for events to be processed...");
    std::thread::sleep(Duration::from_millis(500));

    // Trigger a flush to upload pending events
    println!("Flushing timeline to Datadog...");
    timeline_handle.flush();
    std::thread::sleep(Duration::from_millis(200));

    // Now shutdown our timeline worker
    println!("Shutting down timeline worker...");
    match timeline_handle.shutdown(Duration::from_secs(5)) {
        Ok(()) => println!("Timeline shutdown complete"),
        Err(e) => eprintln!("Timeline shutdown error: {:?}", e),
    }
}
