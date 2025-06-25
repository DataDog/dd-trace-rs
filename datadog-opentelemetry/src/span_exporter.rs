// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{self},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use data_pipeline::trace_exporter::{
    error::TraceExporterError, TraceExporter, TraceExporterBuilder, TraceExporterOutputFormat,
};
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    trace::SpanData,
    Resource,
};

use crate::ddtrace_transform;

/// A reasonnable amount of time that shouldn't impact the app while allowing
/// the leftover data to be almost always flushed
const SPAN_EXPORTER_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// The number of spans that will be buffered before we decide to flush
const SPAN_FLUSH_THRESHOLD: usize = 3000;

/// The maximum number of spans that will be buffered before we drop data
const MAX_BUFFERED_SPANS: usize = 10_000;

/// The maximum amount of time we will wait for a flush to happen  before we flush whatever is in
/// the buffer
const MAX_BATCH_TIME: Duration = Duration::from_secs(1);

struct TraceChunk {
    chunk: Vec<SpanData>,
}

/// Error that can occur when the batch has reached it's maximum size
/// and we can't add more spans to it.
///
/// The added spans will be dropped.
#[derive(Debug, PartialEq, Eq)]
struct BatchFullError {
    spans_dropped: usize,
}

/// Error that can occur when the mutex was poisoned.
///
/// The only way to handle it is to log and try to exit cleanly
struct MutexPoisonnedError;

#[derive(Debug, PartialEq, Eq)]
enum SenderError {
    AlreadyShutdown,
    TimedOut,
    MutexPoisonned,
    BatchFull(BatchFullError),
}

struct Batch {
    chunks: Vec<TraceChunk>,
    last_flush: std::time::Instant,
    span_count: usize,
    max_buffered_spans: usize,
}

// Pre-allocate the batch buffer to avoid reallocations on small sizes.
// Trace chunk is 24 bytes, so this takes 24 * 400 = 9.6kB
const PRE_ALLOCATE_CHUNKS: usize = 400;

impl Batch {
    fn new(max_buffered_spans: usize) -> Self {
        Self {
            chunks: Vec::with_capacity(PRE_ALLOCATE_CHUNKS),
            last_flush: std::time::Instant::now(),
            span_count: 0,
            max_buffered_spans,
        }
    }

    fn span_count(&self) -> usize {
        self.span_count
    }

    /// Add a trace chunk to the batch
    /// If the batch is already too big, drop the chunk and return an error
    ///
    /// This method will not check that adding the chunk will not exceed the maximum size of the
    /// batch. So the batch can be over the maximum size after this call.
    /// This is because we don't want to always drop traces that contain more spans than the maximum
    /// size.
    fn add_trace_chunk(&mut self, chunk: Vec<SpanData>) -> Result<(), BatchFullError> {
        if self.span_count > self.max_buffered_spans {
            return Err(BatchFullError {
                spans_dropped: chunk.len(),
            });
        }
        if chunk.is_empty() {
            return Ok(());
        }
        let chunk_len: usize = chunk.len();
        self.chunks.push(TraceChunk { chunk });
        self.span_count += chunk_len;
        Ok(())
    }

    /// Export the trace chunk and reset the batch
    fn export(&mut self) -> Vec<TraceChunk> {
        let chunks = std::mem::replace(&mut self.chunks, Vec::with_capacity(PRE_ALLOCATE_CHUNKS));
        self.span_count = 0;
        self.last_flush = std::time::Instant::now();
        chunks
    }
}

/// Datadog exporter
///
/// This exporter will spawn a worker thread where the trace exporter runs.
/// When a trace chunk, it will be added buffered until:
/// * The number of spans in the buffer is greater than SPAN_FLUSH_THRESHOLD
/// * The time since the last flush is greater than MAX_BATCH_TIME
/// * A force flush, or shutdown is triggered
pub struct DatadogExporter {
    trace_exporter: TraceExporterHandle,
    tx: Sender,
}

impl DatadogExporter {
    pub fn new(config: dd_trace::Config) -> Self {
        let (tx, rx) = channel(SPAN_FLUSH_THRESHOLD, MAX_BUFFERED_SPANS);
        let trace_exporter = {
            let mut builder = TraceExporterBuilder::default();
            builder
                .set_language("rust")
                .set_url(config.trace_agent_url())
                .set_dogstatsd_url(config.dogstatsd_agent_url())
                .set_tracer_version(config.tracer_version())
                .set_language_version(config.language_version())
                .set_service(config.service())
                .set_output_format(TraceExporterOutputFormat::V04)
                .set_client_computed_top_level();
            if config.enable_stats() {
                builder.enable_stats(Duration::from_secs(10));
            }
            if let Some(env) = config.env() {
                builder.set_env(env);
            }
            if let Some(version) = config.version() {
                builder.set_app_version(version);
            }
            TraceExporterWorker::spawn(config, builder, rx, Resource::builder_empty().build())
        };
        Self { trace_exporter, tx }
    }

    pub fn export_chunk_no_wait(&self, span_data: Vec<SpanData>) -> OTelSdkResult {
        let chunk_len = span_data.len();
        if chunk_len == 0 {
            return Ok(());
        }

        match self.tx.add_trace_chunk(span_data) {
            Err(SenderError::AlreadyShutdown) => {
                self.join()?;
                Err(OTelSdkError::InternalFailure(
                    "DatadogExporter: trace exporter has already shutdown".to_string(),
                ))
            }
            Err(e) => Err(OTelSdkError::InternalFailure(format!(
                "DatadogExporter: failed to add trace chunk: {:?}",
                e
            ))),
            Ok(()) => Ok(()),
        }
    }

    pub fn set_resource(&self, resource: Resource) -> OTelSdkResult {
        match self.tx.set_resource(resource) {
            Err(SenderError::AlreadyShutdown) => {
                self.join()?;
                Err(OTelSdkError::InternalFailure(
                    "DatadogExporter: trace exporter has already shutdown".to_string(),
                ))
            }
            Err(e) => Err(OTelSdkError::InternalFailure(format!(
                "DatadogExporter: failed to set resource: {:?}",
                e
            ))),
            Ok(()) => Ok(()),
        }
    }

    pub fn force_flush(&self) -> OTelSdkResult {
        match self.tx.trigger_flush() {
            Err(SenderError::AlreadyShutdown) => {
                self.join()?;
                Err(OTelSdkError::InternalFailure(
                    "DatadogExporter: trace exporter has already shutdown".to_string(),
                ))
            }
            Err(e) => Err(OTelSdkError::InternalFailure(format!(
                "DatadogExporter: failed to trigger flush: {:?}",
                e
            ))),
            Ok(()) => Ok(()),
        }
    }

    pub fn shutdown(&self) -> OTelSdkResult {
        match self
            .tx
            .trigger_shutdown()
            .and_then(|()| self.tx.wait_shutdown_done(SPAN_EXPORTER_SHUTDOWN_TIMEOUT))
        {
            Ok(()) | Err(SenderError::BatchFull(_)) => {}
            Err(SenderError::AlreadyShutdown) => {
                self.join()?;
                return Err(OTelSdkError::InternalFailure(
                    "DatadogExporter: trace exporter has already shutdown".to_string(),
                ));
            }
            Err(e) => {
                return Err(OTelSdkError::InternalFailure(format!(
                    "DatadogExporter: trace exporter shutdown failed {:?}",
                    e,
                )));
            }
        };
        self.join()
    }

    fn join(&self) -> OTelSdkResult {
        self.trace_exporter
            .handle
            .lock()
            .map_err(|_| {
                OTelSdkError::InternalFailure(
                    "DatadogExporter: can't access worker task join handle".to_string(),
                )
            })?
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

impl fmt::Debug for DatadogExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatadogExporter").finish()
    }
}

fn channel(flush_trigger_number_of_spans: usize, max_number_of_spans: usize) -> (Sender, Receiver) {
    let waiter = Arc::new(Waiter {
        state: Mutex::new(SharedState {
            flush_needed: false,
            shutdown_needed: false,
            has_shutdown: false,
            batch: Batch::new(max_number_of_spans),
            set_resource: None,
        }),
        notifier: Condvar::new(),
    });
    (
        Sender {
            waiter: waiter.clone(),
            flush_trigger_number_of_spans,
        },
        Receiver { waiter },
    )
}

struct Sender {
    waiter: Arc<Waiter>,
    flush_trigger_number_of_spans: usize,
}

impl Drop for Sender {
    fn drop(&mut self) {
        let _ = self.trigger_shutdown();
    }
}

impl Sender {
    fn get_state(&self) -> Result<MutexGuard<'_, SharedState>, SenderError> {
        self.waiter
            .state
            .lock()
            .map_err(|_| SenderError::MutexPoisonned)
    }

    fn get_running_state(&self) -> Result<MutexGuard<'_, SharedState>, SenderError> {
        let state = self.get_state()?;
        if state.has_shutdown {
            return Err(SenderError::AlreadyShutdown);
        }
        Ok(state)
    }

    fn add_trace_chunk(&self, chunk: Vec<SpanData>) -> Result<(), SenderError> {
        let mut state = self.get_running_state()?;
        state
            .batch
            .add_trace_chunk(chunk)
            .map_err(SenderError::BatchFull)?;
        if state.batch.span_count() > self.flush_trigger_number_of_spans {
            state.flush_needed = true;
            self.waiter.notifier.notify_all();
        }
        Ok(())
    }

    /// Set the otel resource to be used for the next trace mapping
    fn set_resource(&self, resource: Resource) -> Result<(), SenderError> {
        let mut state = self.get_running_state()?;
        state.set_resource = Some(resource);
        self.waiter.notifier.notify_all();
        Ok(())
    }

    fn trigger_flush(&self) -> Result<(), SenderError> {
        let mut state = self.get_running_state()?;
        state.flush_needed = true;
        self.waiter.notifier.notify_all();
        Ok(())
    }

    fn trigger_shutdown(&self) -> Result<(), SenderError> {
        let mut state = self.get_running_state()?;
        state.shutdown_needed = true;
        self.waiter.notifier.notify_all();
        Ok(())
    }

    fn wait_shutdown_done(&self, timeout: Duration) -> Result<(), SenderError> {
        if timeout.is_zero() {
            return Err(SenderError::TimedOut);
        }
        let mut state = self.get_state()?;
        let deadline = Instant::now() + timeout;
        let mut leftover = timeout;
        while !state.has_shutdown {
            let res;
            (state, res) = self
                .waiter
                .notifier
                .wait_timeout(state, leftover)
                .map_err(|_| SenderError::TimedOut)?;
            if res.timed_out() {
                return Err(SenderError::MutexPoisonned);
            }
            leftover = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
        }
        Ok(())
    }
}

struct Receiver {
    waiter: Arc<Waiter>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.shutdown_done();
    }
}

impl Receiver {
    fn shutdown_done(&self) -> Result<(), MutexPoisonnedError> {
        let mut state = self.waiter.state.lock().map_err(|_| MutexPoisonnedError)?;
        state.has_shutdown = true;
        self.waiter.notifier.notify_all();
        Ok(())
    }

    fn receive(
        &self,
        timeout: Duration,
    ) -> Result<(TraceExporterMessage, Vec<TraceChunk>), MutexPoisonnedError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.waiter.state.lock().map_err(|_| MutexPoisonnedError)?;
        loop {
            if let Some(res) = state.set_resource.take() {
                return Ok((TraceExporterMessage::SetResource { resource: res }, vec![]));
            }
            // If shutdown was asked, grab the batch and shutdown
            if state.shutdown_needed {
                return Ok((TraceExporterMessage::Shutdown, state.batch.export()));
            }
            // If we need to flush, grab the batch and reset the flag
            if state.flush_needed {
                state.flush_needed = false;
                return Ok((TraceExporterMessage::FlushTraceChunks, state.batch.export()));
            }
            let leftover = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            let timeout_result;
            (state, timeout_result) = self.waiter.notifier.wait_timeout(state, leftover).unwrap();
            if timeout_result.timed_out() {
                // If we hit timeout, flush whatever is in the batch
                return Ok((
                    TraceExporterMessage::FlushTraceChunksWithTimeout,
                    state.batch.export(),
                ));
            }
        }
    }
}

struct SharedState {
    flush_needed: bool,
    shutdown_needed: bool,
    has_shutdown: bool,
    batch: Batch,
    set_resource: Option<Resource>,
}

struct Waiter {
    state: Mutex<SharedState>,
    notifier: Condvar,
}

struct TraceExporterWorker {
    cfg: dd_trace::Config,
    trace_exporter: TraceExporter,
    rx: Receiver,
    otel_resoure: opentelemetry_sdk::Resource,
}

impl TraceExporterWorker {
    /// Spawn a new thread to run the trace exporter
    /// and return a handle to it.
    /// The thread will run until either
    /// * The handle is dropped
    /// * A shutdown flag is set
    /// * The thread panics
    fn spawn(
        cfg: dd_trace::Config,
        builder: TraceExporterBuilder,
        rx: Receiver,
        otel_resoure: opentelemetry_sdk::Resource,
    ) -> TraceExporterHandle {
        let handle = thread::spawn({
            move || {
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
                    otel_resoure,
                };
                task.run()
            }
        });
        TraceExporterHandle {
            handle: Mutex::new(Some(handle)),
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
        while let Ok((message, data)) = self.rx.receive(MAX_BATCH_TIME) {
            if !data.is_empty() {
                match self.export_trace_chunks(data) {
                    Ok(()) => {}
                    Err(e) => {
                        dd_trace::dd_error!("DatadogExporter: Export error {}", e,);
                    }
                };
            }
            match message {
                TraceExporterMessage::Shutdown => break,
                TraceExporterMessage::FlushTraceChunks
                | TraceExporterMessage::FlushTraceChunksWithTimeout => {}
                TraceExporterMessage::SetResource { resource } => {
                    self.otel_resoure = resource;
                }
            }
        }
        self.trace_exporter
            .shutdown(Some(SPAN_EXPORTER_SHUTDOWN_TIMEOUT))
    }

    fn export_trace_chunks(&mut self, trace_chunks: Vec<TraceChunk>) -> OTelSdkResult {
        let trace_chunks = trace_chunks
            .into_iter()
            .map(|TraceChunk { chunk }| -> Vec<_> {
                ddtrace_transform::otel_trace_chunk_to_dd_trace_chunk(
                    &self.cfg,
                    chunk,
                    &self.otel_resoure,
                )
            })
            .collect();
        match self.trace_exporter.send_trace_chunks(trace_chunks) {
            Ok(agent_response) => {
                self.handle_agent_reponse(agent_response);
                Ok(())
            }
            Err(e) => Err(OTelSdkError::InternalFailure(e.to_string())),
        }
    }

    fn handle_agent_reponse(&self, _agent_response: String) {
        // TODO: handle agent response
    }
}

#[derive(Debug, PartialEq)]
enum TraceExporterMessage {
    FlushTraceChunks,
    FlushTraceChunksWithTimeout,
    SetResource {
        resource: opentelemetry_sdk::Resource,
    },
    Shutdown,
}

struct TraceExporterHandle {
    handle: Mutex<Option<thread::JoinHandle<Result<(), TraceExporterError>>>>,
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::{borrow::Cow, time::Duration};

    use opentelemetry::SpanId;
    use opentelemetry_sdk::trace::{SpanData, SpanEvents, SpanLinks};

    use crate::span_exporter::{BatchFullError, SenderError};

    use super::channel;

    fn empty_span_data() -> SpanData {
        SpanData {
            span_context: opentelemetry::trace::SpanContext::empty_context(),
            parent_span_id: SpanId::INVALID,
            name: Cow::Borrowed(""),
            start_time: std::time::SystemTime::now(),
            end_time: std::time::SystemTime::now(),
            attributes: vec![],
            events: SpanEvents::default(),
            links: SpanLinks::default(),
            status: opentelemetry::trace::Status::Unset,
            dropped_attributes_count: 0,
            span_kind: opentelemetry::trace::SpanKind::Internal,
            instrumentation_scope: opentelemetry::InstrumentationScope::default(),
        }
    }

    #[test]
    fn test_receiver_sender_flush() {
        let (tx, rx) = channel(2, 4);
        std::thread::scope(|s| {
            s.spawn(|| tx.add_trace_chunk(vec![empty_span_data()]));
            s.spawn(|| tx.add_trace_chunk(vec![empty_span_data(), empty_span_data()]));

            let (message, chunks) = rx
                .receive(time::Duration::from_secs(1))
                .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));

            assert_eq!(message, super::TraceExporterMessage::FlushTraceChunks);
            assert_eq!(chunks.len(), 2);
        });
    }

    #[test]
    fn test_receiver_sender_batch_drop() {
        let (tx, rx) = channel(2, 4);
        for i in 1..=3 {
            tx.add_trace_chunk(vec![empty_span_data(); i]).unwrap();
        }

        assert_eq!(
            tx.add_trace_chunk(vec![empty_span_data(); 4]),
            Err(SenderError::BatchFull(BatchFullError { spans_dropped: 4 }))
        );

        let (message, chunks) = rx
            .receive(time::Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));
        assert_eq!(message, super::TraceExporterMessage::FlushTraceChunks);
        assert_eq!(chunks.len(), 3);
        for (i, chunk) in chunks.into_iter().enumerate() {
            assert_eq!(chunk.chunk.len(), i + 1);
        }
    }

    #[test]
    fn test_receiver_sender_timeout() {
        let (tx, rx) = channel(2, 4);
        std::thread::scope(|s| {
            s.spawn(|| tx.add_trace_chunk(vec![empty_span_data()]));
            s.spawn(|| {
                let (message, chunks) = rx
                    .receive(time::Duration::from_millis(1))
                    .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));

                assert_eq!(
                    message,
                    super::TraceExporterMessage::FlushTraceChunksWithTimeout
                );
                assert_eq!(chunks.len(), 1);
            });
        });
    }

    #[test]
    fn test_trigger_shutdown() {
        let (tx, rx) = channel(2, 4);
        std::thread::scope(|s| {
            s.spawn(|| tx.add_trace_chunk(vec![empty_span_data()]).unwrap());
            s.spawn(|| {
                tx.add_trace_chunk(vec![empty_span_data(), empty_span_data()])
                    .unwrap()
            });
            s.spawn(|| tx.trigger_shutdown().unwrap());
        });
        let (message, batch) = rx
            .receive(Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));
        assert_eq!(message, super::TraceExporterMessage::Shutdown);
        assert_eq!(batch.len(), 2);

        let (message, batch) = rx
            .receive(Duration::from_secs(1))
            .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));
        assert_eq!(message, super::TraceExporterMessage::Shutdown);
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_wait_for_shutdown() {
        let (tx, rx) = channel(2, 4);

        std::thread::scope(|s| {
            s.spawn(|| {
                tx.trigger_shutdown()
                    .unwrap_or_else(|_| panic!("Failed to trigger shutdown"));
                tx.wait_shutdown_done(Duration::from_secs(1))
                    .unwrap_or_else(|_| panic!("Failed to wait for shutdown"));
            });
            s.spawn(|| {
                let (msg, batch) = rx
                    .receive(Duration::from_secs(1))
                    .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));
                assert_eq!(msg, super::TraceExporterMessage::Shutdown);
                assert_eq!(batch.len(), 0);
                drop(rx);
            });
        });
    }

    #[test]
    fn test_already_shutdown() {
        let (tx, rx) = channel(2, 4);
        drop(rx);
        assert_eq!(tx.trigger_shutdown(), Err(SenderError::AlreadyShutdown));
    }
}
