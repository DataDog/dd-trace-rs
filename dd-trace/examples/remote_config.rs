// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Example of using the remote configuration client to update sampling rules

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use dd_trace::configuration::remote_config::RemoteConfigClient;
use dd_trace::Config;

fn main() {
    // Create initial configuration
    let mut builder = Config::builder();
    builder.set_service("remote-config-example".to_string());
    builder.set_log_level_filter(dd_trace::log::LevelFilter::Debug);

    let config = Arc::new(Mutex::new(builder.build()));

    println!("Starting remote configuration client...");
    if let Ok(cfg) = config.lock() {
        println!("Initial sampling rules: {:?}", cfg.trace_sampling_rules());
    }

    // Create remote config client
    let client =
        RemoteConfigClient::new(config.clone()).expect("Failed to create remote config client");

    // The client now directly updates the config when new rules arrive
    // No callbacks needed - the config is automatically updated

    // Start the client in background
    let _handle = client.start();

    println!("Remote config client started. Listening for configuration updates...");
    println!("Press Ctrl+C to exit");

    // Keep main thread alive to observe updates
    loop {
        thread::sleep(Duration::from_secs(10));

        // Periodically print current configuration
        if let Ok(cfg) = config.lock() {
            println!(
                "\nCurrent sampling rules count: {}",
                cfg.trace_sampling_rules().len()
            );
        }
    }
}
