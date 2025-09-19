// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    any::Any,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::Error;
use ddtelemetry::{
    data::{self, Configuration},
    worker::{self, TelemetryWorkerHandle},
};

use crate::{configuration::ConfigurationProvider, dd_debug, dd_error, dd_info, dd_warn, Config};

static TELEMETRY: OnceLock<Arc<Mutex<Telemetry>>> = OnceLock::new();

trait TelemetryHandle: Sync + Send + 'static + Any {
    fn add_error_log(
        &mut self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error>;

    fn add_configuration(&mut self, configuration: Configuration) -> Result<(), anyhow::Error>;

    fn send_start(&self, config: Option<&Config>) -> Result<(), anyhow::Error>;

    fn send_stop(&self) -> Result<(), anyhow::Error>;

    #[allow(dead_code)]
    fn as_any(&self) -> &dyn Any;
}

impl TelemetryHandle for TelemetryWorkerHandle {
    fn add_error_log(
        &mut self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error> {
        self.add_log(message.clone(), message, data::LogLevel::Error, stack_trace)
    }

    fn add_configuration(&mut self, config_item: Configuration) -> Result<(), anyhow::Error> {
        self.try_send_msg(worker::TelemetryActions::AddConfig(config_item))
    }

    fn send_start(&self, config: Option<&Config>) -> Result<(), anyhow::Error> {
        if let Some(config) = config {
            config
                .get_telemetry_configuration()
                .into_iter()
                .for_each(|config_provider| {
                    self.try_send_msg(worker::TelemetryActions::AddConfig(
                        config_provider.get_configuration(None),
                    ))
                    .ok();
                });
        }

        self.send_start()
    }

    fn send_stop(&self) -> Result<(), anyhow::Error> {
        self.send_stop()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Default)]
struct Telemetry {
    handle: Option<Box<dyn TelemetryHandle>>,
    enabled: bool,
    log_collection_enabled: bool,
}

pub fn init_telemetry(config: &Config) {
    init_telemetry_inner(config, None, &TELEMETRY);
}

fn init_telemetry_inner(
    config: &Config,
    custom_handle: Option<Box<dyn TelemetryHandle>>,
    telemetry_cell: &OnceLock<Arc<Mutex<Telemetry>>>,
) {
    telemetry_cell.get_or_init(|| match make_telemetry_worker(config, custom_handle) {
        Ok(handle) => {
            handle.send_start(Some(config)).ok();
            Arc::new(Mutex::new(Telemetry {
                handle: Some(handle),
                enabled: config.telemetry_enabled(),
                log_collection_enabled: config.telemetry_log_collection_enabled(),
            }))
        }
        Err(err) => {
            dd_error!("Telemetry: Error initializing worker: {err:?}");
            Arc::new(Mutex::new(Telemetry::default()))
        }
    });
}

fn make_telemetry_worker(
    config: &Config,
    custom_handle: Option<Box<dyn TelemetryHandle>>,
) -> Result<Box<dyn TelemetryHandle>, Error> {
    if custom_handle.is_none() {
        let mut builder = worker::TelemetryWorkerBuilder::new(
            config.trace_agent_url().to_string(),
            config.service().to_string(),
            config.language().to_string(),
            config.language_version().to_string(),
            config.tracer_version().to_string(),
        );
        builder.config = ddtelemetry::config::Config::from_env();
        builder.config.telemetry_heartbeat_interval =
            Duration::from_secs_f64(config.telemetry_heartbeat_interval());
        // builder.config.debug_enabled = true;

        builder
            .run()
            .map(|handle| Box::new(handle) as Box<dyn TelemetryHandle>)
    } else {
        custom_handle.ok_or_else(|| Error::msg("Custom telemetry handle not provided"))
    }
}

pub fn stop_telemetry() {
    stop_telemetry_inner(&TELEMETRY);
}

fn stop_telemetry_inner(telemetry_cell: &OnceLock<Arc<Mutex<Telemetry>>>) {
    let Some(telemetry) = telemetry_cell.get() else {
        return;
    };
    let Ok(telemetry) = telemetry.lock() else {
        return;
    };
    let Some(handle) = &telemetry.handle else {
        return;
    };
    dd_info!("Stopping telemetry");
    handle.send_stop().ok();
}

pub fn add_log_error<I: Into<String>>(message: I, stack: Option<String>) {
    add_log_error_inner(message, stack, &TELEMETRY)
}

// message should be a template and must avoid dynamic messages
fn add_log_error_inner<I: Into<String>>(
    message: I,
    stack: Option<String>,
    telemetry_cell: &OnceLock<Arc<Mutex<Telemetry>>>,
) {
    let Some(telemetry) = telemetry_cell.get() else {
        return;
    };
    let Ok(mut telemetry) = telemetry.lock() else {
        return;
    };
    if !telemetry.enabled || !telemetry.log_collection_enabled {
        return;
    }
    let Some(handle) = telemetry.handle.as_mut() else {
        return;
    };
    handle.add_error_log(message.into(), stack).ok();
}

pub fn notify_configuration_update(
    config_provider: &dyn ConfigurationProvider,
    config_id: Option<String>,
) {
    notify_configuration_update_inner(config_provider, config_id, &TELEMETRY);
}

fn notify_configuration_update_inner(
    config_provider: &dyn ConfigurationProvider,
    config_id: Option<String>,
    telemetry_cell: &OnceLock<Arc<Mutex<Telemetry>>>,
) {
    let Some(telemetry) = telemetry_cell.get() else {
        return;
    };
    let Ok(mut telemetry) = telemetry.lock() else {
        return;
    };
    if !telemetry.enabled {
        return;
    }
    let Some(handle) = telemetry.handle.as_mut() else {
        return;
    };

    if let Err(err) = handle.add_configuration(config_provider.get_configuration(config_id)) {
        dd_warn!("Telemetry: error sending configuration item {err}");
    } else {
        dd_debug!("Telemetry: configuration update sent sucessfully");
    }
}

#[cfg(test)]
mod tests {
    use ddtelemetry::data;

    use crate::{
        configuration::ConfigurationProvider,
        dd_debug, dd_error, dd_warn,
        telemetry::{
            add_log_error_inner, init_telemetry_inner, notify_configuration_update_inner,
            TelemetryHandle, TELEMETRY,
        },
        Config,
    };

    use std::{any::Any, sync::OnceLock};

    struct TestTelemetryHandle {
        pub logs: Vec<(String, data::LogLevel, Option<String>)>,
        pub configurations: Vec<data::Configuration>,
    }

    impl TestTelemetryHandle {
        fn new() -> Self {
            TestTelemetryHandle {
                logs: vec![],
                configurations: vec![],
            }
        }
    }

    impl TelemetryHandle for TestTelemetryHandle {
        fn add_error_log(
            &mut self,
            message: String,
            stack_trace: Option<String>,
        ) -> Result<(), anyhow::Error> {
            self.logs
                .push((message, data::LogLevel::Error, stack_trace));
            Ok(())
        }

        fn add_configuration(
            &mut self,
            configuration: data::Configuration,
        ) -> Result<(), anyhow::Error> {
            self.configurations.push(configuration);
            Ok(())
        }

        fn send_start(&self, _config: Option<&Config>) -> Result<(), anyhow::Error> {
            Ok(())
        }

        fn send_stop(&self) -> Result<(), anyhow::Error> {
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockConfigurationProvider {
        name: String,
        value: String,
        origin: data::ConfigurationOrigin,
    }

    impl MockConfigurationProvider {
        fn new(origin: data::ConfigurationOrigin) -> Self {
            MockConfigurationProvider {
                name: "DD_SERVICE".to_string(),
                value: "test".to_string(),
                origin,
            }
        }
    }

    impl ConfigurationProvider for MockConfigurationProvider {
        fn get_configuration(&self, config_id: Option<String>) -> data::Configuration {
            data::Configuration {
                name: self.name.clone(),
                value: self.value.clone(),
                origin: self.origin.clone(),
                config_id,
            }
        }
    }

    #[test]
    fn test_add_log_error_telemetry_disabled() {
        let config = Config::builder().set_telemetry_enabled(false).build();

        let telemetry_cell = OnceLock::new();
        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &telemetry_cell,
        );

        let message = "test.error.telemetry.disabled";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error_inner(message, stack_trace.clone(), &telemetry_cell);

        let t = telemetry_cell.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        assert!(!handle
            .logs
            .contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error() {
        let config = Config::builder().build();

        let telemetry_cell = OnceLock::new();
        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &telemetry_cell,
        );

        let message = "test.error.default";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error_inner(message, stack_trace.clone(), &telemetry_cell);

        let t = telemetry_cell.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        assert!(handle
            .logs
            .contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error_log_collection_disabled() {
        let config = Config::builder()
            .set_telemetry_log_collection_enabled(false)
            .build();

        let telemetry_cell = OnceLock::new();
        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &telemetry_cell,
        );

        let message = "test.error.log_collection.disabled";
        let stack_trace = Some("At telemetry.rs:42".to_string());
        add_log_error_inner(message, stack_trace.clone(), &telemetry_cell);

        let t = telemetry_cell.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        assert!(!handle
            .logs
            .contains(&(message.to_string(), data::LogLevel::Error, stack_trace)));
    }

    #[test]
    fn test_add_log_error_from_log_macros() {
        let config = Config::builder()
            .set_log_level_filter(crate::log::LevelFilter::Debug)
            .build();

        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &TELEMETRY,
        );

        let expected_messages = [
            "This is an error".to_string(),
            "This is an error with {config:?}".to_string(),
            "This is an error with {:?}".to_string(),
            "This is an error with mutiple {} {}".to_string(),
        ];

        dd_debug!("This is a debug");
        dd_warn!("This is a warn");
        dd_error!("This is an error");
        dd_error!("This is an error with {config:?}");
        dd_error!("This is an error with {:?}", config);
        dd_error!(
            "This is an error with mutiple {} {}",
            "detail 1",
            "detail 2"
        );

        let t = TELEMETRY.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        // Errors are sent via Telemetry
        let logs = handle.logs.clone();
        expected_messages.iter().for_each(|message| {
            let log = logs.iter().find(|(msg, _, _)| msg == message);
            assert!(log.is_some());
            let (_, level, stack_trace) = log.unwrap();

            assert_eq!(*level, data::LogLevel::Error);
            assert!(stack_trace.is_some());
        });

        // Other levels not
        assert!(!logs.iter().any(|(msg, _, _)| msg == "This is an debug"));
        assert!(!logs.iter().any(|(msg, _, _)| msg == "This is an warn"));
    }

    #[test]
    fn test_notify_configuration_update() {
        let config = Config::builder().build();
        let telemetry_cell = OnceLock::new();
        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &telemetry_cell,
        );

        let mock_provider = MockConfigurationProvider::new(data::ConfigurationOrigin::EnvVar);
        let config_id = Some("config-42".to_string());

        notify_configuration_update_inner(&mock_provider, config_id.clone(), &telemetry_cell);

        let t = telemetry_cell.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        assert_eq!(handle.configurations.len(), 1);

        let sent_config = &handle.configurations[0];
        assert_eq!(sent_config.name, "DD_SERVICE");
        assert_eq!(sent_config.value, "test");
        assert_eq!(sent_config.origin, data::ConfigurationOrigin::EnvVar);
        assert_eq!(sent_config.config_id, config_id);
    }

    #[test]
    fn test_notify_configuration_update_telemetry_disabled() {
        let config = Config::builder().set_telemetry_enabled(false).build();
        let telemetry_cell = OnceLock::new();
        init_telemetry_inner(
            &config,
            Some(Box::new(TestTelemetryHandle::new())),
            &telemetry_cell,
        );

        let mock_provider = MockConfigurationProvider::new(data::ConfigurationOrigin::EnvVar);

        notify_configuration_update_inner(&mock_provider, None, &telemetry_cell);

        let t = telemetry_cell.get().unwrap().lock().unwrap();
        let handle = t
            .handle
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<TestTelemetryHandle>()
            .expect("Handle should be TestTelemetryHandle");

        // Should not send configuration when telemetry is disabled
        assert_eq!(handle.configurations.len(), 0);
    }

    #[test]
    fn test_notify_configuration_update_no_handle() {
        let telemetry_cell = OnceLock::new();
        // Don't initialize telemetry - no handle should be present

        let mock_provider = MockConfigurationProvider::new(data::ConfigurationOrigin::Default);

        // Should not panic when no telemetry is initialized
        notify_configuration_update_inner(&mock_provider, None, &telemetry_cell);
    }
}
