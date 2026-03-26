// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Tokio Timeline Example - Diverse Async Patterns
//!
//! This example demonstrates various async patterns to generate interesting timeline data:
//! - Producer/Consumer with channels
//! - Parallel HTTP-like request handling
//! - Mutex contention
//! - Nested task spawning
//! - Different timing patterns
//!
//! # Requirements
//!
//! This feature requires **Tokio's unstable APIs**. You must compile with the `tokio_unstable`
//! cfg flag:
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline
//! ```

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig};
use dial9_tokio_telemetry::telemetry::TracedRuntime;
use tokio::sync::{mpsc, Mutex, Semaphore};

fn main() {
    // Configure Datadog
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service("tokio-timeline-demo".to_string())
        .set_env("development".to_string())
        .set_version("0.1.0".to_string())
        .build();

    // Configure timeline - shorter interval for demo
    let timeline_config = TimelineConfig::builder()
        .upload_interval(Duration::from_secs(10)) // Upload every 10 seconds for faster feedback
        .max_buffered_events(100_000)
        .build();

    // Build the timeline writer
    let (writer, timeline_handle) = timeline()
        .with_config(datadog_config)
        .with_timeline_config(timeline_config)
        .with_channel_capacity(10_000)
        .build_writer()
        .expect("failed to build timeline writer");

    // Create a traced Tokio runtime with 4 workers and task tracking enabled
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.worker_threads(4).enable_all();

    let (runtime, guard) = TracedRuntime::builder()
        .with_task_tracking(true) // Enable task spawn location tracking
        .build_and_start(runtime_builder, Box::new(writer))
        .expect("failed to build traced runtime");

    let handle = guard.handle();

    runtime.block_on(async {
        println!("=== Tokio Timeline Demo (30+ second run) ===\n");
        println!("This demo runs for ~35 seconds to demonstrate proper timeline behavior.\n");

        // Run all demos concurrently
        let h = handle.clone();
        let demo1 = handle.spawn(producer_consumer_demo(h.clone()));

        let h = handle.clone();
        let demo2 = handle.spawn(parallel_requests_demo(h.clone()));

        let h = handle.clone();
        let demo3 = handle.spawn(mutex_contention_demo(h.clone()));

        let h = handle.clone();
        let demo4 = handle.spawn(nested_tasks_demo(h.clone()));

        let h = handle.clone();
        let demo5 = handle.spawn(semaphore_pool_demo(h.clone()));

        // Add a continuous workload that runs for the full duration
        let h = handle.clone();
        let demo6 = handle.spawn(continuous_workload_demo(h.clone()));

        // Wait for all demos
        let _ = tokio::join!(demo1, demo2, demo3, demo4, demo5, demo6);

        println!("\n=== All demos completed! ===");
    });

    // Shutdown sequence is CRITICAL for event delivery!
    //
    // dial9 uses thread-local buffers (1024 event threshold) that only flush when:
    // - Buffer fills up (1024 events)
    // - Worker thread exits (Drop impl on ThreadLocalBuffer)
    // - Explicit flush
    //
    // ORDER MATTERS:
    // 1. Drop runtime first - worker threads exit, flushing thread-local buffers
    // 2. Drop dial9 guard - triggers final flush from collector to our writer
    // 3. Then flush our timeline
    //
    // WRONG order (guard before runtime) causes events to be lost because worker
    // threads are still running and holding unflushed events in their buffers.
    println!("\nShutting down...");

    // 1. Drop runtime - worker threads exit, flushing thread-local buffers
    drop(runtime);

    // 2. Drop dial9 guard - triggers final flush from collector to TraceWriter
    drop(guard);

    // 3. Brief pause to let events propagate through channels
    std::thread::sleep(Duration::from_millis(100));

    // 4. Flush our timeline to upload remaining events
    println!("Flushing timeline...");
    timeline_handle.flush();
    std::thread::sleep(Duration::from_millis(500));

    // 5. Shutdown timeline worker
    match timeline_handle.shutdown(Duration::from_secs(5)) {
        Ok(()) => println!("Timeline shutdown complete"),
        Err(e) => eprintln!("Timeline shutdown error: {:?}", e),
    }
}

/// Demo 1: Producer/Consumer pattern with channels
/// Shows task communication and wake patterns
async fn producer_consumer_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Producer/Consumer] Starting...");

    let (tx, rx) = mpsc::channel::<i32>(10);
    let rx = Arc::new(Mutex::new(rx));

    // Spawn producer
    let producer = handle.spawn(async move {
        for i in 0..20 {
            tx.send(i).await.ok();
            // Variable delay to create interesting patterns
            tokio::time::sleep(Duration::from_millis(10 + (i as u64 % 5) * 10)).await;
        }
        println!("[Producer] Sent 20 messages");
    });

    // Spawn multiple consumers that compete for messages
    let mut consumers = Vec::new();
    for consumer_id in 0..4u64 {
        let rx = Arc::clone(&rx);
        let consumer = handle.spawn(async move {
            let mut count = 0;
            loop {
                // Try to receive with timeout
                let msg = {
                    let mut guard = rx.lock().await;
                    tokio::time::timeout(Duration::from_millis(100), guard.recv()).await
                };

                match msg {
                    Ok(Some(_)) => {
                        count += 1;
                        // Simulate processing with varying times per consumer
                        tokio::time::sleep(Duration::from_millis(20 + consumer_id * 10)).await;
                    }
                    _ => break, // Timeout or channel closed
                }
            }
            println!("[Consumer {}] Processed {} items", consumer_id, count);
        });
        consumers.push(consumer);
    }

    producer.await.ok();
    for c in consumers {
        c.await.ok();
    }

    println!("[Producer/Consumer] Done!");
}

/// Demo 2: Parallel "HTTP requests" with different latencies
/// Shows concurrent I/O-bound tasks
async fn parallel_requests_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Parallel Requests] Starting...");

    let endpoints = vec![
        ("fast-api", 20),
        ("medium-api", 50),
        ("slow-api", 100),
        ("very-slow-api", 200),
        ("instant-api", 5),
    ];

    let mut requests = Vec::new();

    // Simulate 3 rounds of requests
    for round in 0..3 {
        for (endpoint, latency_ms) in &endpoints {
            let endpoint = endpoint.to_string();
            let latency = *latency_ms;

            let request = handle.spawn(async move {
                // Simulate request processing
                tokio::time::sleep(Duration::from_millis(latency)).await;

                // Simulate response parsing
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(5)).await;

                println!(
                    "[Request] Round {} - {} completed ({}ms)",
                    round, endpoint, latency
                );
            });
            requests.push(request);
        }

        // Small delay between rounds
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for req in requests {
        req.await.ok();
    }

    println!("[Parallel Requests] Done!");
}

/// Demo 3: Mutex contention
/// Shows tasks waiting on shared resources
async fn mutex_contention_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Mutex Contention] Starting...");

    let counter = Arc::new(Mutex::new(0i32));
    let mut tasks = Vec::new();

    // Spawn 8 tasks that all try to increment the counter
    for task_id in 0..8 {
        let counter = Arc::clone(&counter);
        let task = handle.spawn(async move {
            for _ in 0..5 {
                // Acquire lock - may block
                let mut guard = counter.lock().await;
                *guard += 1;

                // Hold lock while "processing"
                tokio::time::sleep(Duration::from_millis(10)).await;

                drop(guard);

                // Do some work outside the lock
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            println!("[Mutex Task {}] Done", task_id);
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.ok();
    }

    let final_count = *counter.lock().await;
    println!("[Mutex Contention] Final count: {} (expected: 40)", final_count);
}

/// Demo 4: Nested task spawning
/// Shows parent-child task relationships
async fn nested_tasks_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Nested Tasks] Starting...");

    // Level 0: Root task spawns level 1 tasks
    let mut level1_tasks = Vec::new();

    for l1_id in 0..3 {
        let h = handle.clone();
        let level1 = handle.spawn(async move {
            println!("[Nested L1-{}] Starting", l1_id);

            // Level 1 spawns level 2 tasks
            let mut level2_tasks = Vec::new();

            for l2_id in 0..2 {
                let h2 = h.clone();
                let level2 = h.spawn(async move {
                    println!("[Nested L2-{}-{}] Starting", l1_id, l2_id);

                    // Level 2 spawns level 3 tasks
                    let mut level3_tasks = Vec::new();

                    for l3_id in 0..2 {
                        let level3 = h2.spawn(async move {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            println!("[Nested L3-{}-{}-{}] Done", l1_id, l2_id, l3_id);
                        });
                        level3_tasks.push(level3);
                    }

                    for t in level3_tasks {
                        t.await.ok();
                    }
                    println!("[Nested L2-{}-{}] Done", l1_id, l2_id);
                });
                level2_tasks.push(level2);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;

            for t in level2_tasks {
                t.await.ok();
            }
            println!("[Nested L1-{}] Done", l1_id);
        });
        level1_tasks.push(level1);
    }

    for task in level1_tasks {
        task.await.ok();
    }

    println!("[Nested Tasks] Done!");
}

/// Demo 5: Semaphore-based connection pool
/// Shows limited concurrency patterns
async fn semaphore_pool_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Semaphore Pool] Starting...");

    // Simulate a connection pool with 3 slots
    let pool = Arc::new(Semaphore::new(3));
    let mut tasks = Vec::new();

    // 10 tasks competing for 3 pool slots
    for task_id in 0..10 {
        let pool = Arc::clone(&pool);
        let task = handle.spawn(async move {
            // Wait for a pool slot
            let _permit = pool.acquire().await.unwrap();

            println!("[Pool Task {}] Acquired connection", task_id);

            // Simulate using the connection
            tokio::time::sleep(Duration::from_millis(50)).await;

            println!("[Pool Task {}] Released connection", task_id);
            // permit is dropped here, releasing the slot
        });
        tasks.push(task);
    }

    for task in tasks {
        task.await.ok();
    }

    println!("[Semaphore Pool] Done!");
}

/// Demo 6: Continuous workload that runs for 30+ seconds
/// This ensures the example runs long enough for multiple timeline uploads
async fn continuous_workload_demo(handle: dial9_tokio_telemetry::telemetry::TelemetryHandle) {
    println!("[Continuous Workload] Starting (will run for ~30 seconds)...");

    let start = std::time::Instant::now();
    let duration = Duration::from_secs(30);
    let mut batch = 0;

    while start.elapsed() < duration {
        batch += 1;
        let elapsed = start.elapsed().as_secs();
        println!("[Continuous Workload] Batch {} ({}s elapsed)", batch, elapsed);

        // Spawn a batch of parallel tasks that do varying amounts of work
        let mut tasks = Vec::new();
        for task_id in 0..5 {
            let task = handle.spawn(async move {
                // Simulate CPU work with polling
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                    tokio::time::sleep(Duration::from_millis(10 + task_id * 5)).await;
                }
            });
            tasks.push(task);
        }

        // Wait for batch to complete
        for task in tasks {
            task.await.ok();
        }

        // Small delay between batches
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    println!(
        "[Continuous Workload] Done! Ran {} batches over {:.1}s",
        batch,
        start.elapsed().as_secs_f64()
    );
}
