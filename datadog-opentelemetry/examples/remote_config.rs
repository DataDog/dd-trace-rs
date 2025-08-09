// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating automatic remote configuration integration
//!
//! This example shows how the datadog-opentelemetry crate automatically
//! initializes the RemoteConfigClient when remote configuration is enabled.
//!
//! Run this example with:
//! ```bash
//! cargo run --example remote_config
//! ```
//!
//! The example will:
//! 1. Create a configuration with remote config enabled
//! 2. Initialize the OpenTelemetry tracer (which automatically starts the RemoteConfigClient)
//! 3. Create some test spans
//! 4. Keep running to demonstrate the remote config client working in the background

use std::thread;
use std::time::Duration;

use dd_trace::Config;
use opentelemetry::trace::{Tracer, TracerProvider};
use opentelemetry_sdk::trace::TracerProviderBuilder;

fn main() {
    println!("Starting remote configuration example...");

    // Create configuration with remote config enabled
    let mut builder = Config::builder();
    builder.set_service("remote-config-example".to_string());
    builder.set_remote_config_enabled(true); // Enable remote configuration
    builder.set_log_level_filter(dd_trace::log::LevelFilter::Debug);

    let config = builder.build();

    println!("Initial sampling rules: {:?}", config.trace_sampling_rules());

    // Initialize the OpenTelemetry tracer
    // This automatically starts the RemoteConfigClient in the background
    let tracer_provider = datadog_opentelemetry::init_datadog(
        config,
        TracerProviderBuilder::default(),
        None,
    );

    let tracer = tracer_provider.tracer("remote-config-example");

    println!("Tracer initialized. RemoteConfigClient is running in the background.");
    println!("The client will automatically poll for configuration updates every 5 seconds.");
    println!("Press Ctrl+C to exit");

    // Create some test spans to demonstrate the tracer is working
    for i in 1..=5 {
        tracer.in_span("test-operation", |_cx| {
            println!("Created span {}", i);
            // Simulate some work
            thread::sleep(Duration::from_millis(100));
        });
        
        thread::sleep(Duration::from_secs(2));
    }

    println!("Example completed. The RemoteConfigClient continues running in the background.");
    println!("In a real application, it would keep running and apply any remote configuration updates.");
} 