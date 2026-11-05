// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The configuration banner logged once at startup, when `DD_TRACE_STARTUP_LOGS` is enabled.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Map, Value};

use super::configuration::Config;
use crate::dd_info;

const STARTUP_LOG_PREFIX: &str = "DATADOG TRACER CONFIGURATION";

static STARTUP_LOGGED: AtomicBool = AtomicBool::new(false);

/// Logs the effective configuration, if `DD_TRACE_STARTUP_LOGS` is enabled. It is logged once per
/// process, however many tracers are built.
///
/// The banner is logged at info level, so it is only shown when `DD_LOG_LEVEL` is `info` or
/// `debug`.
pub(crate) fn log_startup_configuration(config: &Config) {
    log_startup_configuration_once(config, &STARTUP_LOGGED);
}

fn log_startup_configuration_once(config: &Config, logged: &AtomicBool) {
    if should_log_startup_configuration(config, logged) {
        dd_info!("{STARTUP_LOG_PREFIX} {}", startup_configuration(config));
    }
}

fn should_log_startup_configuration(config: &Config, logged: &AtomicBool) -> bool {
    config.trace_startup_logs() && !logged.swap(true, Ordering::Relaxed)
}

/// The tracer metadata and the effective value of every configuration reported to telemetry.
/// Sensitive configurations are left out, as they are for telemetry.
pub(crate) fn startup_configuration(config: &Config) -> Value {
    let mut configuration = Map::new();
    for provider in config.get_telemetry_configuration() {
        if let Some(effective) = provider
            .get_all_configurations()
            .into_iter()
            .max_by_key(|c| c.seq_id)
        {
            configuration.insert(
                effective.name,
                effective.value.map(Value::String).unwrap_or(Value::Null),
            );
        }
    }

    serde_json::json!({
        "version": config.tracer_version(),
        "lang": config.language(),
        "lang_version": config.language_version(),
        "os_name": std::env::consts::OS,
        "runtime_id": config.runtime_id(),
        "configuration": configuration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startup_configuration() {
        let mut builder = Config::builder();
        builder.set_service("my-service".to_string());
        let config = builder.build();

        let startup = startup_configuration(&config);
        assert_eq!(startup["lang"], "rust");
        assert_eq!(startup["version"], config.tracer_version());
        assert_eq!(startup["runtime_id"], config.runtime_id());
        // The effective value, not the default
        assert_eq!(startup["configuration"]["DD_SERVICE"], "my-service");
        assert_eq!(startup["configuration"]["DD_TRACE_STARTUP_LOGS"], "true");
    }

    #[test]
    fn test_should_log_startup_configuration_once() {
        let logged = AtomicBool::new(false);
        let mut builder = Config::builder();
        builder.set_trace_startup_logs(false);
        let disabled = builder.build();
        let enabled = Config::builder().build();

        // A tracer with startup logs disabled doesn't prevent a later one from logging
        assert!(!should_log_startup_configuration(&disabled, &logged));
        assert!(should_log_startup_configuration(&enabled, &logged));
        assert!(!should_log_startup_configuration(&enabled, &logged));
    }
}
