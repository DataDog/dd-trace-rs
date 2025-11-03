// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    any::Any,
    ops::DerefMut,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use anyhow::Error;
use ddtelemetry::{
    data,
    metrics::ContextKey,
    worker::{self, TelemetryWorkerHandle},
};

use crate::{dd_debug, dd_error, Config};

static TELEMETRY: TelemetryCell = OnceLock::new();

type TelemetryCell = OnceLock<Mutex<Telemetry>>;

struct TelemetryProjection<'a> {
    handle: &'a mut dyn TelemetryHandle,
    log_collection_enabled: bool,
}

fn with_telemetry_handle<F: FnOnce(TelemetryProjection) -> R, R>(
    cell: &TelemetryCell,
    f: F,
) -> Option<R> {
    let mut telemetry = cell.get()?.lock().ok()?;
    if !telemetry.enabled {
        return None;
    }
    let telemetry = telemetry.deref_mut();
    let handle = telemetry.handle.as_mut()?;

    Some(f(TelemetryProjection {
        handle: handle.as_mut(),
        log_collection_enabled: telemetry.log_collection_enabled,
    }))
}

macro_rules! telemetry_metrics {
    ($($variant:ident => ($name:expr, $ns:expr, $ty:expr, [ $($key:expr => $val:expr),* $(,)?] ),)*) => {
        #[derive(PartialEq)]
        pub enum TelemetryMetric {
            $(
                $variant ,
            )*
        }

        const TELEMETRY_METRICS_COUNT: usize = [$(TelemetryMetric :: $variant ,)*].len();

        impl TelemetryMetric {
            fn ddtelemetry_metric_info(
                &self,
            ) -> (
                &'static str,
                data::metrics::MetricNamespace,
                data::metrics::MetricType,
                Vec<ddcommon::tag::Tag>
            ) {
                use data::metrics::MetricNamespace::*;
                use data::metrics::MetricType::*;
                use TelemetryMetric::*;
                match self {
                    $(
                        $variant => ($name, $ns, $ty, vec![
                            $(
                                ddcommon::tag!($key, $val)
                            )*
                        ]),
                    )*
                }
            }

            fn idx(&self) -> usize {
                [$(TelemetryMetric :: $variant ,)*]
                    .into_iter().enumerate()
                    .find(|(_, v)| v == self)
                    .unwrap()
                    .0
            }
        }
    };
}

telemetry_metrics!(
    SpansCreated => ("spans_created", Tracers, Count, []),
    SpansFinished => ("spans_finished", Tracers, Count, []),
    SpansEnqueuedForSerialization => ("spans_enqueued_for_serialization", Tracers, Count, []),
    SpansDroppedBufferFull => ("spans_dropped", Tracers, Count, ["reason" => "overfull_buffer"]),
    TraceSegmentsCreated => ("trace_chunks_created", Tracers, Count, []),
    TraceSegmentsClosed => ("trace_chunks_closed", Tracers, Count, []),
);

trait TelemetryHandle: Sync + Send + 'static + Any {
    fn add_point(&self, value: f64, metric: TelemetryMetric) -> Result<(), anyhow::Error>;

    fn add_error_log(
        &mut self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error>;

    fn send_start(&self, config: Option<&Config>) -> Result<(), anyhow::Error>;

    fn send_stop(&self) -> Result<(), anyhow::Error>;

    #[allow(dead_code)]
    fn as_any(&self) -> &dyn Any;
}

struct TelemetryHandleWrapper {
    handle: TelemetryWorkerHandle,
    metrics_context: [OnceLock<ContextKey>; TELEMETRY_METRICS_COUNT],
}

impl TelemetryHandle for TelemetryHandleWrapper {
    fn add_point(&self, value: f64, metric: TelemetryMetric) -> Result<(), anyhow::Error> {
        let idx = metric.idx();

        let context_key = self.metrics_context[idx].get_or_init(|| {
            let (n, ns, ty, tags) = metric.ddtelemetry_metric_info();
            self.handle
                .register_metric_context(n.to_string(), tags, ty, true, ns)
        });
        self.handle.add_point(value, context_key, vec![])
    }

    fn add_error_log(
        &mut self,
        message: String,
        stack_trace: Option<String>,
    ) -> Result<(), anyhow::Error> {
        self.handle
            .add_log(message.clone(), message, data::LogLevel::Error, stack_trace)
    }

    fn send_start(&self, config: Option<&Config>) -> Result<(), anyhow::Error> {
        if let Some(config) = config {
            config
                .get_telemetry_configuration()
                .into_iter()
                .for_each(|config_item| {
                    self.handle
                        .try_send_msg(worker::TelemetryActions::AddConfig(config_item))
                        .ok();
                });
        }

        self.handle.send_start()
    }

    fn send_stop(&self) -> Result<(), anyhow::Error> {
        self.handle.send_stop()
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
    telemetry_cell: &TelemetryCell,
) {
    telemetry_cell.get_or_init(|| match make_telemetry_worker(config, custom_handle) {
        Ok(handle) => {
            handle.send_start(Some(config)).ok();
            Mutex::new(Telemetry {
                handle: Some(handle),
                enabled: config.telemetry_enabled(),
                log_collection_enabled: config.telemetry_log_collection_enabled(),
            })
        }
        Err(err) => {
            dd_error!("Telemetry: Error initializing worker: {err:?}");
            Mutex::new(Telemetry::default())
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
        builder.runtime_id = Some(config.runtime_id().to_string());
        builder.config = ddtelemetry::config::Config::from_env();
        builder.config.telemetry_heartbeat_interval =
            Duration::from_secs_f64(config.telemetry_heartbeat_interval());
        // builder.config.debug_enabled = true;

        builder.run().map(|handle| {
            Box::new(TelemetryHandleWrapper {
                handle,
                metrics_context: [const { OnceLock::new() }; TELEMETRY_METRICS_COUNT],
            }) as Box<dyn TelemetryHandle>
        })
    } else {
        custom_handle.ok_or_else(|| Error::msg("Custom telemetry handle not provided"))
    }
}

pub fn stop_telemetry() {
    stop_telemetry_inner(&TELEMETRY);
}

fn stop_telemetry_inner(telemetry_cell: &TelemetryCell) {
    with_telemetry_handle(telemetry_cell, |t| {
        dd_debug!("Stopping telemetry");
        t.handle.send_stop().ok();
    });
}

pub fn add_point(value: f64, metric: TelemetryMetric) {
    add_point_inner(value, metric, &TELEMETRY)
}

fn add_point_inner(value: f64, metric: TelemetryMetric, telemetry_cell: &TelemetryCell) {
    with_telemetry_handle(telemetry_cell, |t| {
        t.handle.add_point(value, metric).ok();
    });
}

pub fn add_log_error<I: Into<String>>(message: I, stack: Option<String>) {
    add_log_error_inner(message, stack, &TELEMETRY)
}

// message should be a template and must avoid dynamic messages
fn add_log_error_inner<I: Into<String>>(
    message: I,
    stack: Option<String>,
    telemetry_cell: &TelemetryCell,
) {
    with_telemetry_handle(telemetry_cell, |t| {
        if t.log_collection_enabled {
            t.handle.add_error_log(message.into(), stack).ok();
        }
    });
}

#[cfg(test)]
mod tests {
    use anyhow::Ok;
    use ddtelemetry::data;

    use crate::{
        dd_debug, dd_error, dd_warn,
        telemetry::{
            add_log_error_inner, init_telemetry_inner, TelemetryHandle, TelemetryMetric, TELEMETRY,
        },
        Config,
    };

    use std::{any::Any, sync::OnceLock};

    #[derive(Clone)]
    struct TestTelemetryHandle {
        pub logs: Vec<(String, data::LogLevel, Option<String>)>,
    }

    impl TestTelemetryHandle {
        fn new() -> Self {
            TestTelemetryHandle { logs: vec![] }
        }
    }

    impl TelemetryHandle for TestTelemetryHandle {
        fn add_point(&self, _value: f64, _metric: TelemetryMetric) -> Result<(), anyhow::Error> {
            Ok(())
        }
        fn add_error_log(
            &mut self,
            message: String,
            stack_trace: Option<String>,
        ) -> Result<(), anyhow::Error> {
            self.logs
                .push((message, data::LogLevel::Error, stack_trace));
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
}
