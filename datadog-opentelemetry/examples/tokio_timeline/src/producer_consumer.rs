// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Producer/Consumer Pattern Example
//!
//! Demonstrates channel-based communication between async tasks. Shows wake events
//! when consumers are notified of new messages.
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo run -p tokio_timeline --bin producer_consumer
//! ```

use std::sync::Arc;
use std::time::Duration;

use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig};
use dial9_tokio_telemetry::telemetry::TracedRuntime;
use tokio::sync::{mpsc, Mutex};

fn main() {
    let datadog_config = datadog_opentelemetry::configuration::Config::builder()
        .set_service("tokio-timeline-producer-consumer".to_string())
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
        println!("=== Producer/Consumer Pattern ===\n");

        let (tx, rx) = mpsc::channel::<i32>(10);
        let rx = Arc::new(Mutex::new(rx));

        // Producer: sends messages with variable delays
        let producer = handle.spawn(async move {
            for i in 0..50 {
                tx.send(i).await.ok();
                // Variable delay creates interesting timeline patterns
                tokio::time::sleep(Duration::from_millis(20 + (i as u64 % 5) * 20)).await;
            }
            println!("[Producer] Sent 50 messages");
        });

        // Multiple consumers competing for messages
        let mut consumers = Vec::new();
        for consumer_id in 0..4u64 {
            let rx = Arc::clone(&rx);
            let consumer = handle.spawn(async move {
                let mut count = 0;
                loop {
                    let msg = {
                        let mut guard = rx.lock().await;
                        tokio::time::timeout(Duration::from_millis(200), guard.recv()).await
                    };

                    match msg {
                        Ok(Some(_)) => {
                            count += 1;
                            // Processing time varies by consumer
                            tokio::time::sleep(Duration::from_millis(30 + consumer_id * 15)).await;
                        }
                        _ => break,
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
