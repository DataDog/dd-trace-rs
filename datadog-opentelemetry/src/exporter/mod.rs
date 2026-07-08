// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{self},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use crate::{dd_debug, dd_error};
use libdd_capabilities_impl::NativeCapabilities;
use libdd_data_pipeline::trace_exporter::{
    agent_response::AgentResponse,
    error::{self as trace_exporter_error, TraceExporterError},
    TraceExporter, TraceExporterBuilder,
};

#[derive(Clone, Copy)]
pub struct AsyncExporterConfig {
    /// Whether the async exporter waits for the trace chunks to be exported before returning from
    /// export_chunk
    pub synchronous_writes: bool,
    /// The maximum amount of time the export_chunk waits for a flush if synchronous_writes is
    /// enabled
    pub synchronous_writes_timeout: Option<Duration>,
    /// The maximum amount of time between two flushes
    pub max_flush_interval: Duration,
    /// The maximum number of spans that will be buffered before we drop data
    pub max_buffered_spans: usize,
    /// The number of spans that will be buffered before we decide to flush
    pub span_flush_threshold: usize,
    /// The duration we will wait for the trace exporter to shutdown before returning
    pub trace_exporter_shutdown_timeout: Option<Duration>,
}

impl Default for AsyncExporterConfig {
    fn default() -> Self {
        Self {
            synchronous_writes: false,
            synchronous_writes_timeout: None,
            max_flush_interval: Duration::from_secs(2),
            max_buffered_spans: 10_000,
            span_flush_threshold: 3_000,
            // A reasonable amount of time that shouldn't impact the app while allowing
            // the leftover data to be almost always flushed
            trace_exporter_shutdown_timeout: Some(Duration::from_secs(1)),
        }
    }
}

#[derive(Debug)]
pub struct TraceChunk<T> {
    pub chunk: Vec<T>,
}

/// Error that can occur when the batch has reached its maximum size
/// and we can't add more spans to it.
///
/// The added spans will be dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchFullError {
    spans_dropped: usize,
}

/// Error that can occur when the mutex was poisoned.
///
/// The only way to handle it is to log and try to return an empty but valid state
#[derive(Debug)]
struct MutexPoisonedError;

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncExporterError {
    AlreadyShutdown,
    TimedOut(std::time::Duration),
    MutexPoisoned,
    BatchFull(BatchFullError),
    Panic(String),
}

struct Batch<T> {
    chunks: Vec<TraceChunk<T>>,
    last_flush: std::time::Instant,
    span_count: usize,
    max_buffered_spans: usize,
    batch_gen: BatchGeneration,
}

// Pre-allocate the batch buffer to avoid reallocations on small sizes.
// A trace chunk is 24 bytes, so this takes 24 * 400 = 9.6kB
const PRE_ALLOCATE_CHUNKS: usize = 400;

impl<T> Batch<T> {
    fn new(max_buffered_spans: usize) -> Self {
        let mut batch_gen = BatchGeneration::default();
        batch_gen.incr();
        Self {
            chunks: Vec::with_capacity(PRE_ALLOCATE_CHUNKS),
            last_flush: std::time::Instant::now(),
            span_count: 0,
            batch_gen,
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
    fn add_trace_chunk(&mut self, chunk: Vec<T>) -> Result<(), BatchFullError> {
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
    fn export(&mut self) -> Vec<TraceChunk<T>> {
        let chunks = std::mem::replace(&mut self.chunks, Vec::with_capacity(PRE_ALLOCATE_CHUNKS));
        self.span_count = 0;
        self.last_flush = std::time::Instant::now();
        if !chunks.is_empty() {
            self.batch_gen.incr();
        }
        chunks
    }
}

/// # AsyncTraceExporter
///
/// Creating an instance of the AsyncTraceExporter will spawn a background thread that
/// periodically sends trace chunks through the TraceExporter
///
/// # Buffering behavior
///
/// Unless in synchronous mode, when [`AsyncTraceExporter::send_chunk`] is called, the trace chunk
/// will be buffered until:
/// * The number of spans in the buffer is greater than
///   [`AsyncExporterConfig::span_flush_threshold`]
/// * The time since the last flush is greater than [`AsyncExporterConfig::max_flush_interval`]
/// * [`AsyncTraceExporter::force_flush`], or [`AsyncTraceExporter::trigger_shutdown`] are called.
///   Both of these methods trigger a flush, but do not wait for the flush to be done before
///   returning
///
/// # Synchronous mode
///
/// If [`AsyncExporterConfig::synchronous_writes`] is true and
/// [`AsyncExporterConfig::synchronous_writes_timeout`] is not None,
/// calls to [`AsyncTraceExporter::send_chunk`] will wait
/// * Either until the chunks have been flushed the agent
/// * Or the `synchronous_writes_timeout` duration is reached. At which point the flush might
///   continue in the background
pub struct AsyncTraceExporter<T> {
    trace_exporter: TraceExporterHandle,
    tx: Sender<T>,
    /// Enables synchronous exports if Some
    ///
    /// Each batch in the queue will get a generation associated. Generations are strictly
    /// incremental and processed in order by the background thread.
    /// When the background thread processes a batch it will increment it's 'last_flushed_batch'
    /// and an export can wait until the 'last_flushed_batch' is equal to the batch it added it's
    /// trace chunks to.
    synchronous_export: Option<Duration>,
}

impl<T: Send + 'static> AsyncTraceExporter<T> {
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: AsyncExporterConfig,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
        exporter: Box<dyn Exporter<T> + Send>,
        trace_exporter_builder: TraceExporterBuilder<libdd_shared_runtime::ForkSafeRuntime>,
    ) -> Self {
        let (tx, rx) = channel(
            config.span_flush_threshold,
            config.max_buffered_spans,
            config.synchronous_writes,
        );
        let trace_exporter = {
            TraceExporterWorker::spawn(
                trace_exporter_builder,
                rx,
                agent_response_handler,
                exporter,
                config,
            )
        };
        Self {
            trace_exporter,
            tx,
            synchronous_export: config
                .synchronous_writes
                .then_some(config.synchronous_writes_timeout)
                .flatten(),
        }
    }

    pub fn send_chunk(&self, trace_chunk: Vec<T>) -> Result<(), AsyncExporterError> {
        let chunk_len = trace_chunk.len();
        if chunk_len == 0 {
            return Ok(());
        }

        match self.tx.add_trace_chunk(trace_chunk) {
            Err(AsyncExporterError::AlreadyShutdown) => {
                self.join()?;
                Err(AsyncExporterError::AlreadyShutdown)
            }
            Ok(flush_gen) => {
                if let Some(timeout) = self.synchronous_export {
                    self.tx.wait_flush_done(flush_gen, timeout)?;
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn force_flush(&self) -> Result<(), AsyncExporterError> {
        match self.tx.trigger_flush() {
            Err(AsyncExporterError::AlreadyShutdown) => {
                self.join()?;
                Err(AsyncExporterError::AlreadyShutdown)
            }
            e => e,
        }
    }

    pub fn trigger_shutdown(&self) {
        use AsyncExporterError::*;
        match self.tx.trigger_shutdown() {
            Err(AlreadyShutdown | MutexPoisoned) => {}
            Err(e @ (TimedOut(_) | BatchFull(_) | Panic(_))) => {
                // This should logically never happen, so log an error and continue
                dd_error!(
                    "DatadogExporter.trigger_shutdown: unexpected error failed to trigger shutdown: {:?}",
                    e,
                );
            }
            Ok(()) => {}
        }
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), AsyncExporterError> {
        use AsyncExporterError::*;
        match self.tx.wait_shutdown_done(timeout) {
            Err(AlreadyShutdown) => {
                self.join()?;
                Err(AsyncExporterError::AlreadyShutdown)
            }
            Ok(()) | Err(MutexPoisoned) => self.join(),
            e => e,
        }
    }

    fn join(&self) -> Result<(), AsyncExporterError> {
        let handle = self
            .trace_exporter
            .handle
            .lock()
            .map_err(|_| AsyncExporterError::MutexPoisoned)?
            .take();
        handle
            .ok_or(AsyncExporterError::AlreadyShutdown)?
            .join()
            .map_err(|p| {
                if let Some(panic) = p
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| p.downcast_ref::<&str>().copied())
                {
                    AsyncExporterError::Panic(panic.to_string())
                } else {
                    AsyncExporterError::Panic("error message unknown".to_string())
                }
            })?
            .or_else(|e| match e {
                TraceExporterError::Shutdown(trace_exporter_error::ShutdownError::TimedOut(t)) => {
                    Err(AsyncExporterError::TimedOut(t))
                }
                e => {
                    log_trace_exporter_error(&e);
                    Ok(())
                }
            })
    }

    pub fn queue_metrics(&self) -> QueueMetricsFetcher<T> {
        QueueMetricsFetcher {
            waiter: self.tx.waiter.clone(),
        }
    }
}

impl<T> fmt::Debug for AsyncTraceExporter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatadogExporter").finish()
    }
}

pub struct QueueMetricsFetcher<T> {
    waiter: Arc<Waiter<T>>,
}

impl<T> QueueMetricsFetcher<T> {
    pub fn get_metrics(&self) -> QueueMetrics {
        let Some(mut state) = self.waiter.state.lock().ok() else {
            return QueueMetrics::default();
        };
        std::mem::take(&mut state.metrics)
    }
}

#[derive(Default)]
pub struct QueueMetrics {
    pub spans_dropped_full_buffer: usize,
    pub spans_queued: usize,
}

fn channel<T>(
    flush_trigger_number_of_spans: usize,
    max_number_of_spans: usize,
    synchronous_write: bool,
) -> (Sender<T>, Receiver<T>) {
    let waiter = Arc::new(Waiter {
        state: Mutex::new(SharedState {
            flush_needed: false,
            last_flush_generation: BatchGeneration::default(),
            shutdown_needed: false,
            has_shutdown: false,
            batch: Batch::new(max_number_of_spans),
            metrics: QueueMetrics::default(),
        }),
        notifier: Condvar::new(),
    });
    (
        Sender {
            waiter: waiter.clone(),
            flush_trigger_number_of_spans,
            synchronous_write,
        },
        Receiver { waiter },
    )
}

struct Sender<T> {
    waiter: Arc<Waiter<T>>,
    flush_trigger_number_of_spans: usize,
    synchronous_write: bool,
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let _ = self.trigger_shutdown();
    }
}

impl<T> Sender<T> {
    fn wait_flush_done(
        &self,
        flush_gen: BatchGeneration,
        timeout: Duration,
    ) -> Result<(), AsyncExporterError> {
        if timeout.is_zero() {
            return Err(AsyncExporterError::TimedOut(Duration::ZERO));
        }
        let state = self.get_state()?;
        let (_state, res) = self
            .waiter
            .notifier
            .wait_timeout_while(state, timeout, |state| {
                state.last_flush_generation < flush_gen && !state.has_shutdown
            })
            .map_err(|_| AsyncExporterError::MutexPoisoned)?;
        if res.timed_out() {
            return Err(AsyncExporterError::TimedOut(timeout));
        }
        Ok(())
    }

    fn get_state(&self) -> Result<MutexGuard<'_, SharedState<T>>, AsyncExporterError> {
        self.waiter
            .state
            .lock()
            .map_err(|_| AsyncExporterError::MutexPoisoned)
    }

    fn get_running_state(&self) -> Result<MutexGuard<'_, SharedState<T>>, AsyncExporterError> {
        let state = self.get_state()?;
        if state.has_shutdown {
            return Err(AsyncExporterError::AlreadyShutdown);
        }
        Ok(state)
    }

    fn add_trace_chunk(&self, chunk: Vec<T>) -> Result<BatchGeneration, AsyncExporterError> {
        let mut state = self.get_running_state()?;
        let chunk_len = chunk.len();
        if let Err(e @ BatchFullError { spans_dropped }) = state.batch.add_trace_chunk(chunk) {
            state.metrics.spans_dropped_full_buffer += spans_dropped;
            return Err(AsyncExporterError::BatchFull(e));
        }
        state.metrics.spans_queued += chunk_len;
        let gen = state.batch.batch_gen;
        if state.batch.span_count() > self.flush_trigger_number_of_spans || self.synchronous_write {
            state.flush_needed = true;
            self.waiter.notify_all(state);
        }
        Ok(gen)
    }

    fn trigger_flush(&self) -> Result<(), AsyncExporterError> {
        let mut state = self.get_running_state()?;
        state.flush_needed = true;
        self.waiter.notify_all(state);
        Ok(())
    }

    fn trigger_shutdown(&self) -> Result<(), AsyncExporterError> {
        let mut state = self.get_running_state()?;
        state.shutdown_needed = true;
        self.waiter.notify_all(state);
        Ok(())
    }

    fn wait_shutdown_done(&self, timeout: Duration) -> Result<(), AsyncExporterError> {
        if timeout.is_zero() {
            return Err(AsyncExporterError::TimedOut(Duration::ZERO));
        }
        let state = self.get_state()?;
        let (_state, res) = self
            .waiter
            .notifier
            .wait_timeout_while(state, timeout, |state| !state.has_shutdown)
            .map_err(|_| AsyncExporterError::MutexPoisoned)?;
        if res.timed_out() {
            return Err(AsyncExporterError::TimedOut(timeout));
        }
        Ok(())
    }
}

struct Receiver<T> {
    waiter: Arc<Waiter<T>>,
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let _ = self.shutdown_done();
    }
}

impl<T> Receiver<T> {
    fn shutdown_done(&self) -> Result<(), MutexPoisonedError> {
        let mut state = self.waiter.state.lock().map_err(|_| MutexPoisonedError)?;
        state.has_shutdown = true;
        self.waiter.notify_all(state);
        Ok(())
    }

    fn receive(
        &self,
        timeout: Duration,
    ) -> Result<(TraceExporterMessage, Vec<TraceChunk<T>>), MutexPoisonedError> {
        let mut state = self.waiter.state.lock().map_err(|_| MutexPoisonedError)?;
        let deadline = state.batch.last_flush + timeout;
        loop {
            // If shutdown was asked, grab the batch and shutdown
            if state.shutdown_needed {
                return Ok((TraceExporterMessage::Shutdown, state.batch.export()));
            }
            // If we need to flush, grab the batch and reset the flag
            if state.flush_needed {
                state.flush_needed = false;
                return Ok((TraceExporterMessage::FlushTraceChunks, state.batch.export()));
            }
            let leftover = deadline.saturating_duration_since(Instant::now());
            let timed_out;
            (state, timed_out) = if leftover == Duration::ZERO {
                (state, true)
            } else {
                self.waiter
                    .notifier
                    .wait_timeout(state, leftover)
                    .map(|(s, t)| (s, t.timed_out()))
                    .map_err(|_| MutexPoisonedError)?
            };
            if timed_out {
                // If we hit timeout, flush whatever is in the batch
                return Ok((
                    TraceExporterMessage::FlushTraceChunksWithTimeout,
                    state.batch.export(),
                ));
            }
        }
    }

    fn ack_export(&self) -> Result<(), MutexPoisonedError> {
        let mut state = self.waiter.state.lock().map_err(|_| MutexPoisonedError)?;
        state.last_flush_generation.incr();
        self.waiter.notify_all(state);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
struct BatchGeneration(usize);

impl BatchGeneration {
    fn incr(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }
}

struct SharedState<T> {
    flush_needed: bool,
    last_flush_generation: BatchGeneration,
    shutdown_needed: bool,
    has_shutdown: bool,
    batch: Batch<T>,
    metrics: QueueMetrics,
}

struct Waiter<T> {
    state: Mutex<SharedState<T>>,
    notifier: Condvar,
}

impl<T> Waiter<T> {
    #[inline(always)]
    fn notify_all(&self, state: MutexGuard<'_, SharedState<T>>) {
        drop(state);
        self.notifier.notify_all();
    }
}

pub trait Exporter<T> {
    fn trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<T>>,
        trace_exporter: &TraceExporter<NativeCapabilities, libdd_shared_runtime::ForkSafeRuntime>,
    ) -> Result<AgentResponse, TraceExporterError>;
}

struct TraceExporterWorker<T> {
    trace_exporter: TraceExporter<NativeCapabilities, libdd_shared_runtime::ForkSafeRuntime>,
    rx: Receiver<T>,
    exporter: Box<dyn Exporter<T>>,
    #[allow(clippy::type_complexity)]
    agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    config: AsyncExporterConfig,
}

impl<T: Send + 'static> TraceExporterWorker<T> {
    /// Spawn a new thread to run the trace exporter
    /// and return a handle to it.
    /// The thread will run until either
    /// * The handle is dropped
    /// * A shutdown flag is set
    /// * The thread panics
    #[allow(clippy::type_complexity)]
    fn spawn(
        builder: TraceExporterBuilder<libdd_shared_runtime::ForkSafeRuntime>,
        rx: Receiver<T>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
        exporter: Box<dyn Exporter<T> + Send>,
        config: AsyncExporterConfig,
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
                    rx,
                    agent_response_handler,
                    exporter,
                    config,
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
            let start = std::time::Instant::now();
            let timeout = Duration::from_secs(5);
            while libdd_data_pipeline::agent_info::get_agent_info().is_none() {
                if start.elapsed() > timeout {
                    panic!("Timeout waiting for agent info to be ready");
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        while let Ok((message, data)) = self.rx.receive(self.config.max_flush_interval) {
            if !data.is_empty() {
                match self.export_trace_chunks(data) {
                    Ok(()) => {}
                    Err(e) => log_trace_exporter_error(&e),
                };
                if let Err(MutexPoisonedError) = self.rx.ack_export() {
                    break;
                }
            }
            match message {
                TraceExporterMessage::Shutdown => break,
                TraceExporterMessage::FlushTraceChunks
                | TraceExporterMessage::FlushTraceChunksWithTimeout => {}
            }
        }
        self.trace_exporter
            .shutdown(self.config.trace_exporter_shutdown_timeout)
    }

    fn export_trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<T>>,
    ) -> Result<(), TraceExporterError> {
        let agent_response = self
            .exporter
            .trace_chunks(trace_chunks, &self.trace_exporter)?;
        self.handle_agent_response(agent_response);
        Ok(())
    }

    fn handle_agent_response(&self, agent_response: AgentResponse) {
        match agent_response {
            AgentResponse::Unchanged => {}
            AgentResponse::Changed { body } => {
                if let Some(ref handler) = self.agent_response_handler {
                    (handler)(&body);
                }
            }
        }
    }
}

#[track_caller]
fn log_trace_exporter_error(e: &TraceExporterError) {
    match e {
        // Exceptional errors
        TraceExporterError::Builder(e) => {
            dd_error!("DatadogExporter: Export error: Builder error: {}", e);
        }
        TraceExporterError::Internal(
            trace_exporter_error::InternalErrorKind::InvalidWorkerState(state),
        ) => {
            dd_error!(
                "DatadogExporter: Export error: Internal error: Invalid worker state: {}",
                state
            );
        }

        // Runtime errors
        TraceExporterError::Deserialization(e) => {
            dd_debug!(
                "DatadogExporter: Export error: Deserialization error: {}",
                e
            );
        }
        TraceExporterError::Io(error) => {
            dd_debug!("DatadogExporter: Export error: IO error: {}", error);
        }
        TraceExporterError::Network(e) => {
            dd_debug!("DatadogExporter: Export error: Network error: {}", e);
        }
        TraceExporterError::Request(e) => {
            dd_debug!("DatadogExporter: Export error: Request error: {}", e);
        }
        TraceExporterError::Serialization(error) => {
            dd_debug!(
                "DatadogExporter: Export error: Serialization error: {}",
                error
            );
        }
        TraceExporterError::Agent(trace_exporter_error::AgentErrorKind::EmptyResponse) => {
            dd_debug!("DatadogExporter: Export error: Agent error: empty response");
        }
        TraceExporterError::Shutdown(
            libdd_data_pipeline::trace_exporter::error::ShutdownError::TimedOut(duration),
        ) => {
            dd_debug!(
                "DatadogExporter: Export error: Shutdown error: timed out after {}ms",
                duration.as_millis()
            );
        }
        TraceExporterError::Telemetry(e) => {
            dd_debug!(
                "DatadogExporter: Export error: Instrumentation telemetry error: {}",
                e
            );
        }
    };
}

#[derive(Debug, PartialEq)]
enum TraceExporterMessage {
    FlushTraceChunks,
    FlushTraceChunksWithTimeout,
    Shutdown,
}

struct TraceExporterHandle {
    handle: Mutex<Option<thread::JoinHandle<Result<(), TraceExporterError>>>>,
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::time::Duration;

    use crate::exporter::{AsyncExporterError, BatchFullError};

    use super::channel;

    #[test]
    fn test_receiver_sender_flush() {
        let (tx, rx) = channel(2, 4, false);
        std::thread::scope(|s| {
            s.spawn(|| tx.add_trace_chunk(vec![()]));
            s.spawn(|| tx.add_trace_chunk(vec![(), ()]));

            let (message, chunks) = rx
                .receive(time::Duration::from_secs(1))
                .unwrap_or_else(|_| panic!("Failed to receive trace chunk"));

            assert_eq!(message, super::TraceExporterMessage::FlushTraceChunks);
            assert_eq!(chunks.len(), 2);
        });
    }

    #[test]
    fn test_receiver_sender_batch_drop() {
        let (tx, rx) = channel(2, 4, false);
        for i in 1..=3 {
            tx.add_trace_chunk(vec![(); i]).unwrap();
        }

        assert_eq!(
            tx.add_trace_chunk(vec![(); 4]),
            Err(AsyncExporterError::BatchFull(BatchFullError {
                spans_dropped: 4
            }))
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
        let (tx, rx) = channel(2, 4, false);
        std::thread::scope(|s| {
            let _ = s.spawn(|| tx.add_trace_chunk(vec![()])).join();
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
        let (tx, rx) = channel(2, 4, false);
        std::thread::scope(|s| {
            s.spawn(|| tx.add_trace_chunk(vec![()]).unwrap());
            s.spawn(|| tx.add_trace_chunk(vec![(), ()]).unwrap());
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
        let (tx, rx) = channel::<()>(2, 4, false);

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
        let (tx, rx) = channel::<()>(2, 4, false);
        drop(rx);
        assert_eq!(
            tx.trigger_shutdown(),
            Err(AsyncExporterError::AlreadyShutdown)
        );
    }

    #[test]
    fn test_wait_export_synchronously() {
        let (tx, rx) = channel(2, 4, false);

        let gen = tx.add_trace_chunk(vec![(), ()]).unwrap();
        match tx.wait_flush_done(gen, Duration::from_nanos(1)) {
            Err(AsyncExporterError::TimedOut(_)) => {}
            _ => panic!("wait_flush_done should have timed out"),
        }
        assert!(rx.ack_export().is_ok());
        assert!(tx.wait_flush_done(gen, Duration::from_nanos(1)).is_ok())
    }
}
