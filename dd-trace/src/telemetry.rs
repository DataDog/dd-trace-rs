// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use ddtelemetry::{
    data::{self},
    worker::{self, TelemetryWorkerHandle},
};

use crate::{dd_debug, dd_error, dd_info, Config};

static INIT_TELEMETRY_LOCK: Mutex<()> = Mutex::new(());

static TELEMETRY: OnceLock<Arc<Mutex<Telemetry>>> = OnceLock::new();

pub trait TelemetryHandle: Sync + Send + 'static {
    fn add_error_log(
        &self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error>;

    fn send_start(&self) -> Result<(), anyhow::Error>;

    fn send_stop(&self) -> Result<(), anyhow::Error>;
}

impl TelemetryHandle for TelemetryWorkerHandle {
    fn add_error_log(
        &self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error> {
        self.add_log(message.clone(), message, data::LogLevel::Error, stack_trace)
    }

    fn send_start(&self) -> Result<(), anyhow::Error> {
        self.send_start()
    }

    fn send_stop(&self) -> Result<(), anyhow::Error> {
        self.send_stop()
    }
}

struct Telemetry {
    handle: Option<Box<dyn TelemetryHandle>>,
    enabled: bool,
    log_collection_enabled: bool,
}

pub fn init_telemetry(
    config: &Config,
    service_name: Option<String>,
    custom_handle: Option<Box<dyn TelemetryHandle>>,
) {
    let _guard = INIT_TELEMETRY_LOCK.lock().unwrap();

    if let Some(telemetry) = TELEMETRY.get() {
        dd_debug!("Updating already initialized telemetry");

        let mut telemetry = telemetry.lock().unwrap();
        telemetry.enabled = config.telemetry_enabled();
        telemetry.log_collection_enabled = config.telemetry_log_collection_enabled();

        return;
    } else if !config.telemetry_enabled() {
        dd_info!("Telemetry not enabled");
        return;
    }

    let handle: Option<Box<dyn TelemetryHandle>> = if custom_handle.is_none() {
        let mut builder = worker::TelemetryWorkerBuilder::new(
            "127.0.0.1".to_string(), // FIXME
            service_name.unwrap_or(config.service().to_string()),
            config.language().to_string(),
            config.language_version().to_string(),
            config.tracer_version().to_string(),
        );
        builder.config = ddtelemetry::config::Config::from_env();
        builder.config.telemetry_heartbeat_interval =
            Duration::from_secs_f64(config.telemetry_heartbeat_interval());
        // builder.config.debug_enabled = true;

        match builder.run() {
            Ok(handle) => Some(Box::new(handle)),
            Err(err) => {
                dd_error!("Error initializing telemetry worker: {err:?}");
                None
            }
        }
    } else {
        custom_handle
    };

    if let Some(ref handle) = handle {
        handle.send_start().ok();
    };

    if TELEMETRY
        .set(Arc::new(Mutex::new(Telemetry {
            handle,
            enabled: config.telemetry_enabled(),
            log_collection_enabled: config.telemetry_log_collection_enabled(),
        })))
        .is_err()
    {
        dd_error!("Error initializing telemetry");
    }
}

pub fn stop_telemetry() {
    if let Some(telemetry) = TELEMETRY.get() {
        if let Ok(telemetry) = telemetry.lock() {
            if let Some(ref handle) = telemetry.handle {
                dd_info!("Stopping telemetry");
                handle.send_stop().ok();
            }
        }
    }
}

// message should be a template and must avoid dynamic messages
pub fn add_log_error<I: Into<String>>(message: I, stack: Option<String>) {
    if let Some(telemetry) = TELEMETRY.get() {
        if let Ok(telemetry) = telemetry.lock() {
            if telemetry.enabled && telemetry.log_collection_enabled {
                if let Some(handle) = &telemetry.handle {
                    handle.add_error_log(message.into(), stack).ok();
                }
            }
        }
    }
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use ddtelemetry::data;

    use crate::{
        dd_error,
        telemetry::{add_log_error, init_telemetry, TelemetryHandle},
        Config,
    };

    use std::sync::Mutex;

    static LOGS: Mutex<Vec<(String, data::LogLevel, Option<String>)>> = Mutex::new(vec![]);

    fn clear_logs() {
        LOGS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn logs() -> std::sync::MutexGuard<'static, Vec<(String, data::LogLevel, Option<String>)>> {
        LOGS.lock().unwrap_or_else(|e| e.into_inner())
    }

    struct TestTelemetryHandle {}

    impl TelemetryHandle for TestTelemetryHandle {
        fn add_error_log(
            &self,
            message: String,
            stack_trace: Option<String>,
        ) -> Result<(), anyhow::Error> {
            let mut logs = LOGS.lock().unwrap_or_else(|e| e.into_inner());
            logs.push((message, data::LogLevel::Error, stack_trace));
            Ok(())
        }

        fn send_start(&self) -> Result<(), anyhow::Error> {
            Ok(())
        }

        fn send_stop(&self) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    #[test]
    fn test_add_log_error_telemetry_disabled() {
        clear_logs();

        let config = Config::builder().set_telemetry_enabled(false).build();

        init_telemetry(&config, None, Some(Box::new(TestTelemetryHandle {})));

        let message = "test.error.telemetry.disabled";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error(message, stack_trace.clone());

        assert!(!logs().contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error() {
        clear_logs();

        let config = Config::builder().build();

        init_telemetry(&config, None, Some(Box::new(TestTelemetryHandle {})));

        let message = "test.error.default";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error(message, stack_trace.clone());

        assert!(logs().contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error_log_collection_disabled() {
        clear_logs();

        let config = Config::builder()
            .set_telemetry_log_collection_enabled(false)
            .build();

        init_telemetry(&config, None, Some(Box::new(TestTelemetryHandle {})));

        let message = "test.error.log_collection.disabled";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error(message, stack_trace.clone());

        assert!(!logs().contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error_from_log_macros() {
        clear_logs();

        let config = Config::builder().build();
        init_telemetry(&config, None, Some(Box::new(TestTelemetryHandle {})));

        let expected_messages = [
            "This is an error".to_string(),
            "This is an error with {config:?}".to_string(),
            "This is an error with {:?}".to_string(),
            "This is an error with mutiple {} {}".to_string(),
        ];

        dd_error!("This is an error");
        dd_error!("This is an error with {config:?}");
        dd_error!("This is an error with {:?}", config);
        dd_error!(
            "This is an error with mutiple {} {}",
            "detail 1",
            "detail 2"
        );

        let logs = logs();

        assert_eq!(logs.len(), 4);

        logs.iter().for_each(|(message, level, stack_trace)| {
            assert!(expected_messages.contains(message));
            assert_eq!(*level, data::LogLevel::Error);
            assert!(stack_trace.is_some());
        });
    }
}
