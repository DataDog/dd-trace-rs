// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use opentelemetry::trace::{Tracer, TraceContextExt};
use opentelemetry::Context;
use std::time::Duration;
use tokio::time::sleep;

const SERVICE_NAME: &str = "dd-trace-rs-rc-test-service";

async fn process_request(request_id: u64, request_type: &str) {
    // Create the main span for this request
    let tracer = opentelemetry::global::tracer("request-processor");
    let main_span = tracer.start(format!("process_{}", request_type));
    let cx = Context::current_with_span(main_span);
    
    // Database query - create span, do work, end span
    {
        let db_span = tracer.start_with_context("database_query", &cx);
        let _db_cx = cx.with_span(db_span);
        sleep(Duration::from_millis(20 + (request_id % 30))).await;
    } // span ends here
    
    // External API call - create span, do work, end span  
    {
        let api_span = tracer.start_with_context("external_api_call", &cx);
        let _api_cx = cx.with_span(api_span);
        sleep(Duration::from_millis(30 + (request_id % 40))).await;
    } // span ends here
} // main span ends here

async fn background_worker() {
    let mut counter = 0u64;
    loop {
        counter += 1;
        
        // Simulate different types of requests
        let request_type = match counter % 4 {
            0 => "user_login",
            1 => "data_fetch", 
            2 => "file_upload",
            _ => "analytics_event",
        };
        
        process_request(counter, request_type).await;
        
        // Sleep between requests - emit roughly 2 spans per second
        sleep(Duration::from_millis(500)).await;
        
        // Log every 10 requests to show we're still running
        if counter % 10 == 0 {
            println!("Emitted {} traces so far", counter);
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Starting remote config test application");
    println!("Service name: {}", SERVICE_NAME);
    println!("Agent URL: {}", std::env::var("DD_TRACE_AGENT_URL").unwrap_or_else(|_| "http://localhost:8126".to_string()));

    // Initialize the Datadog tracer with remote config enabled
    let config = dd_trace::Config::builder()
        .set_service(SERVICE_NAME.to_string())
        .set_env("dd-trace-rs-test-env".to_string())
        .set_version("1.0.0".to_string())
        // Remote config is enabled by default, but let's be explicit
        .build();

    // Enable debug logging to see remote config activity
    if std::env::var("DD_LOG_LEVEL").unwrap_or_default().to_lowercase() == "debug" {
        // Note: set_max_level is not public, but the config will handle log level internally
        eprintln!("Debug logging enabled");
    }

    // Verify configuration values
    println!("Config - Service: {}", config.service());
    println!("Config - Environment: {:?}", config.env());
    println!("Config - Version: {:?}", config.version());

    let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(config)
        .init();

    println!("Tracer initialized with remote config enabled");
    println!("Starting to emit spans continuously...");
    println!("You can now create sampling rules in the Datadog backend for service: {}", SERVICE_NAME);
    println!("Press Ctrl+C to stop");

    // Run the background worker that emits spans
    let worker_handle = tokio::spawn(background_worker());

    // Wait for Ctrl+C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Received Ctrl+C, shutting down...");
        }
        _ = worker_handle => {
            println!("Worker finished unexpectedly");
        }
    }

    // Shutdown the tracer to flush remaining spans
    println!("Shutting down tracer...");
    if let Err(e) = tracer_provider.shutdown_with_timeout(Duration::from_secs(5)) {
        eprintln!("Error shutting down tracer: {}", e);
    }
    
    println!("Application stopped");
} 