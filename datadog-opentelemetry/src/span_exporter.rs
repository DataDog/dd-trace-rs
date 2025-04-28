// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt,
    future::{self, Future},
    pin::Pin,
    sync::{self, mpsc::Receiver},
    thread,
    time::Duration,
};

use data_pipeline::trace_exporter::{
    error::TraceExporterError, TraceExporter, TraceExporterBuilder, TraceExporterOutputFormat,
};
use futures::channel::oneshot;
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    trace::SpanData,
};

use crate::ddtrace_transform;

/// A reasonnable amount of time that shouldn't impact the app while allowing
/// the leftover data to be almost always flushed
const SPAN_EXPORTER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Datadog exporter for OpenTelemetry
pub struct DatadogExporter {
    // This exporter will spawn a worked thread where the trace exporter runs.
    // This is to avoid conflicts with the aysnc runtime of the user:
    //
    // The otel sdk SpanExporter api is stupid, export is an async method, but it can be called
    // from a sync context with futures::executor::block_on. So if the exporter is async, it
    // would need to be created inside a tokio runtime... but then the SpanProcessor is it's
    // own thread, which cannot be inside tokio.
    //
    // So we create our own thread to have peace. The exporter currently uses it's own runtime, so
    // building it inside an existing tokio context crashes...
    //
    // The openetelemetry_sdk::trace::BatchSpanProcessor already spawns a thread to batch
    // spans, so we could also probably implement our own SpanProcessor instead of just
    // SpanExporter
    trace_exporter: TraceExporterHandle,
}

impl DatadogExporter {
    pub fn new(config: dd_trace::Config) -> dd_trace::Result<Self> {
        let trace_exporter = {
            let mut builder = TraceExporterBuilder::default();
            builder
                .enable_stats(Duration::from_secs(10))
                .set_language("rust")
                .set_url(config.trace_agent_url())
                .set_dogstatsd_url(config.dogstatsd_agent_url())
                .set_tracer_version(config.tracer_version())
                .set_language_version(config.language_version())
                .set_service(config.service())
                .set_output_format(TraceExporterOutputFormat::V04)
                .set_client_computed_top_level();
            if let Some(env) = config.env() {
                builder.set_env(env);
            }
            if let Some(version) = config.version() {
                builder.set_app_version(version);
            }
            TraceExporterTask::spawn(config, builder)
        };
        Ok(Self { trace_exporter })
    }

    fn export_sync(
        &mut self,
        span_data: Vec<SpanData>,
    ) -> Result<oneshot::Receiver<OTelSdkResult>, OTelSdkError> {
        let (responder, rx) = oneshot::channel();
        if self
            .trace_exporter
            .tx
            .send(TraceExporterMessage::SendSpan {
                span_data,
                responder,
            })
            .is_err()
        {
            // Tracer exporter thread is dead
            self.join()?;
            return Err(OTelSdkError::InternalFailure(
                "Trace exporter background thread has already stopped, without error".to_string(),
            ));
        }
        Ok(rx)
    }

    fn join(&mut self) -> OTelSdkResult {
        self.trace_exporter
            .handle
            .take()
            .ok_or_else(|| {
                OTelSdkError::InternalFailure(
                    "Trace exporter thread has already been stopped".to_string(),
                )
            })?
            .join()
            .map_err(|_| {
                OTelSdkError::InternalFailure("Trace exporter thread panicked".to_string())
            })?
            .map_err(|e| {
                OTelSdkError::InternalFailure(format!("Trace exporter exited with error: {}", e))
            })
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn box_fut<T: Send + Sync + 'static>(t: T) -> BoxFuture<'static, T> {
    Box::pin(future::ready(t))
}

impl opentelemetry_sdk::trace::SpanExporter for DatadogExporter {
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, OTelSdkResult> {
        let rx = match self.export_sync(batch) {
            Ok(rx) => rx,
            Err(e) => return box_fut(Err(e)),
        };
        Box::pin(async {
            match rx.await {
                Ok(res) => res,
                Err(e) => Err(OTelSdkError::InternalFailure(e.to_string())),
            }
        })
    }

    fn shutdown(&mut self) -> OTelSdkResult {
        self.trace_exporter
            .tx
            .send(TraceExporterMessage::Shutdown)
            .map_err(|_| {
                OTelSdkError::InternalFailure("trace exporter has already shutdown".to_string())
            })?;
        self.join()
    }

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        let _ = self
            .trace_exporter
            .tx
            .send(TraceExporterMessage::SetResource {
                resource: resource.clone(),
            });
    }
}

impl fmt::Debug for DatadogExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatadogExporter").finish()
    }
}

struct TraceExporterTask {
    trace_exporter: TraceExporter,
    cfg: dd_trace::Config,
    otel_resoure: opentelemetry_sdk::Resource,
    rx: Receiver<TraceExporterMessage>,
}

impl TraceExporterTask {
    /// Spawn a new thread to run the trace exporter
    /// and return a handle to it.
    /// The thread will run until either
    /// * The handle is dropped
    /// * A shutdown message is sent to the handle
    /// * The thread panics
    fn spawn(cfg: dd_trace::Config, builder: TraceExporterBuilder) -> TraceExporterHandle {
        let (tx, rx) = sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let trace_exporter = match builder.build() {
                Ok(exporter) => exporter,
                Err(e) => {
                    return Err(e);
                }
            };
            let task = Self {
                trace_exporter,
                cfg,
                rx,
                otel_resoure: opentelemetry_sdk::Resource::builder_empty().build(),
            };
            task.run()
        });
        TraceExporterHandle {
            handle: Some(handle),
            tx,
        }
    }

    fn run(mut self) -> Result<(), TraceExporterError> {
        #[cfg(feature = "test-utils")]
        {
            // Wait for the agent info to be fetched to get deterministic output when deciding
            // to drop traces or not
            self.trace_exporter
                .wait_agent_info_ready(Duration::from_secs(5))
                .unwrap();
        }
        loop {
            let Ok(message) = self.rx.recv() else {
                return Ok(());
            };
            match message {
                TraceExporterMessage::SendSpan {
                    span_data,
                    responder,
                } => {
                    if responder
                        .send(self.export_otel_span_data(span_data))
                        .is_err()
                    {
                        // The receiver has been dropped, we could panic or ignore here
                        // No strong opinion...
                        continue;
                    }
                }
                TraceExporterMessage::Shutdown => {
                    return self
                        .trace_exporter
                        .shutdown(Some(SPAN_EXPORTER_SHUTDOWN_TIMEOUT));
                }
                TraceExporterMessage::SetResource { resource } => self.otel_resoure = resource,
            }
        }
    }

    fn export_otel_span_data(&self, span_data: Vec<SpanData>) -> OTelSdkResult {
        let trace_chunks: Vec<Vec<datadog_trace_utils::span::Span<tinybytes::BytesString>>> =
            ddtrace_transform::otel_span_data_to_dd_trace_chunks(
                &self.cfg,
                span_data,
                &self.otel_resoure,
            );
        match self.trace_exporter.send_trace_chunks(trace_chunks) {
            Ok(_rate_reponse) => {
                // TODO: propagate rate response to the sampler configuration
                Ok(())
            }
            Err(e) => Err(OTelSdkError::InternalFailure(e.to_string())),
        }
    }
}

enum TraceExporterMessage {
    SendSpan {
        span_data: Vec<SpanData>,
        responder: oneshot::Sender<OTelSdkResult>,
    },
    SetResource {
        resource: opentelemetry_sdk::Resource,
    },
    Shutdown,
}

struct TraceExporterHandle {
    handle: Option<thread::JoinHandle<Result<(), TraceExporterError>>>,
    tx: sync::mpsc::Sender<TraceExporterMessage>,
}
