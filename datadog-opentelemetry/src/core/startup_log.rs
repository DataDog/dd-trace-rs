// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! The configuration banner logged once at startup, when `DD_TRACE_STARTUP_LOGS` is enabled.

use serde_json::{Map, Value};

use super::configuration::Config;
use super::log::Level;
use crate::dd_log_always;

const STARTUP_LOG_PREFIX: &str = "DATADOG TRACER CONFIGURATION";

/// Logs the effective configuration, if `DD_TRACE_STARTUP_LOGS` is enabled.
///
/// The banner is logged at warn level regardless of `DD_LOG_LEVEL`, since it is enabled by its
/// own setting (see [`dd_log_always!`]).
pub(crate) fn log_startup_configuration(config: &Config) {
    if !config.trace_startup_logs() {
        return;
    }
    dd_log_always!(
        Level::Warn,
        "{STARTUP_LOG_PREFIX} {}",
        startup_configuration(config)
    );
}

/// The tracer metadata and the effective value of every configuration reported to telemetry.
/// Sensitive configurations are left out, as they are for telemetry.
fn startup_configuration(config: &Config) -> Value {
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
}
