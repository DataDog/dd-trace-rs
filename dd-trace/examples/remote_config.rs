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

    let config = Arc::new(builder.build());
    let config_mutex = Arc::new(Mutex::new(config.as_ref().clone()));

    println!("Starting remote configuration client...");
    println!(
        "Initial sampling rules: {:?}",
        config.trace_sampling_rules()
    );

    // Create remote config client
    let mut client =
        RemoteConfigClient::new(config.clone()).expect("Failed to create remote config client");

    // Set up callback to handle configuration updates
    let config_clone = config_mutex.clone();
    client.set_update_callback(move |rules| {
        println!(
            "Received {} new sampling rules from remote config",
            rules.len()
        );

        if let Ok(mut cfg) = config_clone.lock() {
            cfg.update_sampling_rules_from_remote(rules);
            println!("Applied new sampling rules");

            // Print current rules
            for (i, rule) in cfg.trace_sampling_rules().iter().enumerate() {
                println!(
                    "  Rule {}: sample_rate={}, service={:?}, provenance={}",
                    i + 1,
                    rule.sample_rate,
                    rule.service,
                    rule.provenance
                );
            }
        }
    });

    // Start the client in background
    let _handle = client.start();

    println!("Remote config client started. Listening for configuration updates...");
    println!("Press Ctrl+C to exit");

    // Keep main thread alive to observe updates
    loop {
        thread::sleep(Duration::from_secs(10));

        // Periodically print current configuration
        if let Ok(cfg) = config_mutex.lock() {
            println!(
                "\nCurrent sampling rules count: {}",
                cfg.trace_sampling_rules().len()
            );
        }
    }
}
