// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    pin::Pin,
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;
use libdd_capabilities_impl::NativeCapabilities;
use libdd_data_pipeline::trace_buffer::{
    BufferSize, Export, ResponseHandler, TraceBuffer, TraceBufferConfig, TraceBufferError,
    TraceChunk,
};
use libdd_data_pipeline::trace_exporter::{
    agent_response::AgentResponse, error::TraceExporterError, TelemetryConfig, TraceExporter,
    TraceExporterBuilder, TraceExporterOutputFormat,
};
use libdd_shared_runtime::{BasicRuntime, BlockingRuntime, SharedRuntime, SharedRuntimeError};
use opentelemetry_sdk::{trace::SpanData, Resource};

use crate::{
    configuration::Config, core::telemetry_session, ddtrace_transform, mappings::CachedConfig,
};

pub use libdd_data_pipeline::trace_buffer::TraceBufferError as DatadogExporterError;

pub type QueueMetricsFetcher = libdd_data_pipeline::trace_buffer::QueueMetricsFetcher<BufferedSpan>;

/// `SpanData` wrapper that approximates its in-memory size so it can be stored
/// in libdatadog's [`TraceBuffer`].
#[repr(transparent)]
#[derive(Debug)]
pub struct BufferedSpan(SpanData);

// Rough byte-size constants used to convert a `SpanData` into a value the buffer
// can sum to enforce its byte-based capacity. They do not need to be exact — they
// only feed into the buffer's drop / flush thresholds.
const FIXED_SPAN_OVERHEAD: usize = 96;
const ATTRIBUTE_ENTRY_OVERHEAD: usize = 24;
const EVENT_OVERHEAD: usize = 16;
const LINK_OVERHEAD: usize = 32;

fn attr_value_bytes(v: &opentelemetry::Value) -> usize {
    use opentelemetry::{Array, Value};
    match v {
        Value::Bool(_) => 1,
        Value::I64(_) | Value::F64(_) => 8,
        Value::String(s) => s.as_str().len(),
        Value::Array(Array::Bool(a)) => a.len(),
        Value::Array(Array::I64(a)) => a.len() * 8,
        Value::Array(Array::F64(a)) => a.len() * 8,
        Value::Array(Array::String(a)) => a.iter().map(|s| s.as_str().len()).sum(),
        _ => 0,
    }
}

/// Reinterprets a `Vec<SpanData>` as a `Vec<BufferedSpan>` without allocating or
/// moving elements, relying on `BufferedSpan` being `#[repr(transparent)]` over
/// `SpanData`.
fn wrap_span_vec(spans: Vec<SpanData>) -> Vec<BufferedSpan> {
    // SAFETY: `BufferedSpan` is `#[repr(transparent)]` over `SpanData`, so the two
    // types have identical layout, size, and alignment. `Vec` stores its elements
    // in a single contiguous allocation, so reinterpreting the buffer pointer and
    // length/capacity preserves all invariants. We must `mem::forget` the original
    // `Vec` to avoid a double-free of the underlying allocation.
    unsafe {
        let mut spans = std::mem::ManuallyDrop::new(spans);
        Vec::from_raw_parts(
            spans.as_mut_ptr() as *mut BufferedSpan,
            spans.len(),
            spans.capacity(),
        )
    }
}

impl BufferSize for BufferedSpan {
    fn byte_size(&self) -> usize {
        let s = &self.0;
        let mut size: usize = FIXED_SPAN_OVERHEAD;
        size += s.name.len();
        for kv in &s.attributes {
            size += ATTRIBUTE_ENTRY_OVERHEAD + kv.key.as_str().len() + attr_value_bytes(&kv.value);
        }
        for event in s.events.iter() {
            size += EVENT_OVERHEAD + event.name.len();
            for kv in &event.attributes {
                size +=
                    ATTRIBUTE_ENTRY_OVERHEAD + kv.key.as_str().len() + attr_value_bytes(&kv.value);
            }
        }
        for link in s.links.iter() {
            size += LINK_OVERHEAD;
            for kv in &link.attributes {
                size +=
                    ATTRIBUTE_ENTRY_OVERHEAD + kv.key.as_str().len() + attr_value_bytes(&kv.value);
            }
        }
        size
    }
}

/// Counter + cvar tracking spans accepted by `send_chunk` but not yet exported.
type PendingSpans = Arc<(Mutex<usize>, Condvar)>;

pub struct DatadogExporter {
    // Wrapped in `Option` so `Drop` can move them onto a dedicated std thread —
    // their drop transitively drops a `tokio::runtime::Runtime`, which panics when
    // run from inside an async context. See `Drop for DatadogExporter`.
    trace_buffer: Option<TraceBuffer<BufferedSpan>>,
    shared_runtime: Option<Arc<BasicRuntime>>,
    otel_resource: Arc<ArcSwap<Resource>>,
    shutdown_rx: Mutex<Option<mpsc::Receiver<Result<(), SharedRuntimeError>>>>,
    pending_spans: PendingSpans,
}

impl Drop for DatadogExporter {
    fn drop(&mut self) {
        // `tokio::runtime::Runtime::drop` calls `BlockingPool::shutdown`, which performs a
        // blocking wait. That panics when invoked from inside an async context (e.g. when a
        // `DatadogExporter` is dropped at the end of a `#[tokio::test]`). Move all owners of
        // the runtime onto a dedicated std thread so the drop runs outside any tokio context.
        let trace_buffer = self.trace_buffer.take();
        let shared_runtime = self.shared_runtime.take();
        let _ = thread::Builder::new()
            .name("datadog-trace-drop".into())
            .spawn(move || {
                drop(trace_buffer);
                drop(shared_runtime);
            });
    }
}

#[derive(Debug)]
pub enum DatadogExporterInitError {
    Runtime(SharedRuntimeError),
    TraceExporter(TraceExporterError),
    /// Failed to spawn the std thread used to drive trace-exporter construction off the caller's
    /// tokio context.
    BuildThread(std::io::Error),
}

impl std::fmt::Display for DatadogExporterInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "shared runtime init failed: {e}"),
            Self::TraceExporter(e) => write!(f, "trace exporter build failed: {e}"),
            Self::BuildThread(e) => write!(f, "failed to spawn builder thread: {e}"),
        }
    }
}

impl std::error::Error for DatadogExporterInitError {}

type AgentResponseHandler = Box<dyn for<'a> Fn(&'a str) + Send + Sync>;

impl DatadogExporter {
    pub fn new(
        config: Arc<Config>,
        agent_response_handler: Option<AgentResponseHandler>,
    ) -> Result<Self, DatadogExporterInitError> {
        let response_handler = build_response_handler(agent_response_handler);

        // `TraceExporterBuilder::build` drives async setup via `tokio::runtime::Runtime::block_on`,
        // which panics when called from inside an existing tokio runtime (e.g. a `#[tokio::test]`).
        // Run construction on a dedicated std thread so the builder is outside any caller context.
        let (tx, rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("datadog-trace-init".into())
            .spawn(move || {
                let _ = tx.send(build_on_dedicated_thread(config, response_handler));
            })
            .map_err(DatadogExporterInitError::BuildThread)?;
        rx.recv().map_err(|_| {
            DatadogExporterInitError::Runtime(SharedRuntimeError::RuntimeUnavailable)
        })?
    }

    fn trace_buffer(&self) -> &TraceBuffer<BufferedSpan> {
        self.trace_buffer
            .as_ref()
            .expect("trace_buffer accessed after DatadogExporter::drop")
    }

    fn shared_runtime(&self) -> &Arc<BasicRuntime> {
        self.shared_runtime
            .as_ref()
            .expect("shared_runtime accessed after DatadogExporter::drop")
    }

    pub fn queue_metrics(&self) -> QueueMetricsFetcher {
        self.trace_buffer().queue_metrics()
    }

    pub fn send_chunk(&self, span_data: Vec<SpanData>) -> Result<(), TraceBufferError> {
        if span_data.is_empty() {
            return Ok(());
        }
        let n = span_data.len();
        let buffered = wrap_span_vec(span_data);
        // Increment before handing the chunk to libdatadog so the export-side decrement
        // (in `SpanDataExport::export_trace_chunks`) cannot race ahead and underflow.
        increment_pending(&self.pending_spans, n);
        match self.trace_buffer().send_chunk(buffered) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Only `BatchFull` is an outright rejection. Late errors from `wait_flush_done`
                // (sync mode) mean the chunk is still queued.
                if matches!(e, TraceBufferError::BatchFull(_)) {
                    decrement_pending(&self.pending_spans, n);
                }
                Err(e)
            }
        }
    }

    pub fn force_flush(&self) -> Result<(), TraceBufferError> {
        self.trace_buffer().force_flush()
    }

    /// Triggers a flush and blocks until every span accepted by `send_chunk` has been exported
    /// (or the timeout elapses). Use this before [`trigger_shutdown`] so the runtime cancellation
    /// doesn't drop a queued batch.
    pub fn flush_and_drain(&self, timeout: Duration) -> Result<(), TraceBufferError> {
        self.trace_buffer().force_flush()?;
        self.wait_for_drain(timeout)
    }

    fn wait_for_drain(&self, timeout: Duration) -> Result<(), TraceBufferError> {
        let (lock, cvar) = &*self.pending_spans;
        let guard = lock.lock().map_err(|_| TraceBufferError::MutexPoisoned)?;
        if *guard == 0 {
            return Ok(());
        }
        if timeout.is_zero() {
            return Err(TraceBufferError::TimedOut(Duration::ZERO));
        }
        let (_guard, res) = cvar
            .wait_timeout_while(guard, timeout, |count| *count > 0)
            .map_err(|_| TraceBufferError::MutexPoisoned)?;
        if res.timed_out() {
            return Err(TraceBufferError::TimedOut(timeout));
        }
        Ok(())
    }

    pub fn trigger_shutdown(&self) {
        // Kick the worker to drain anything pending while the caller continues shutting other
        // subsystems down in parallel.
        let _ = self.trace_buffer().force_flush();

        let mut slot = match self.shutdown_rx.lock() {
            Ok(slot) => slot,
            Err(_) => return,
        };
        if slot.is_some() {
            return;
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let rt = Arc::clone(self.shared_runtime());
        if thread::Builder::new()
            .name("datadog-trace-shutdown".into())
            .spawn(move || {
                let _ = tx.send(shutdown_basic_runtime(&rt));
            })
            .is_ok()
        {
            *slot = Some(rx);
        }
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), TraceBufferError> {
        let rx = self
            .shutdown_rx
            .lock()
            .map_err(|_| TraceBufferError::MutexPoisoned)?
            .take()
            .ok_or(TraceBufferError::AlreadyShutdown)?;
        let runtime_result = match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(TraceBufferError::TimedOut(timeout)),
            // Shutdown thread vanished before sending — treat as an internal worker error.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(TraceBufferError::TraceExporter(TraceExporterError::Internal(
                    libdd_data_pipeline::trace_exporter::error::InternalErrorKind::InvalidWorkerState(
                        "shutdown thread terminated unexpectedly".to_string(),
                    ),
                )))
            }
        };
        match runtime_result {
            Ok(()) => Ok(()),
            Err(SharedRuntimeError::ShutdownTimedOut(d)) => Err(TraceBufferError::TimedOut(d)),
            Err(SharedRuntimeError::LockFailed(_)) => Err(TraceBufferError::MutexPoisoned),
            Err(SharedRuntimeError::RuntimeUnavailable) => Err(TraceBufferError::AlreadyShutdown),
            Err(e) => Err(TraceBufferError::TraceExporter(TraceExporterError::Internal(
                libdd_data_pipeline::trace_exporter::error::InternalErrorKind::InvalidWorkerState(
                    e.to_string(),
                ),
            ))),
        }
    }

    pub fn set_resource(&self, r: Resource) {
        self.otel_resource.store(Arc::new(r));
    }
}

impl std::fmt::Debug for DatadogExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogExporter").finish()
    }
}

#[allow(clippy::type_complexity)]
fn build_response_handler(agent_response_handler: Option<AgentResponseHandler>) -> ResponseHandler {
    Box::new(move |result| match result {
        Ok(AgentResponse::Changed { body }) => {
            if let Some(handler) = agent_response_handler.as_ref() {
                handler(&body);
            }
        }
        Ok(AgentResponse::Unchanged) => {}
        Err(e) => log_trace_exporter_error(&e),
    })
}

/// Drives trace-exporter construction on a dedicated std thread. `TraceExporterBuilder::build`
/// runs async setup through `Runtime::block_on`, which panics when called from inside an existing
/// tokio runtime — this function must therefore run on a fresh std thread.
fn build_on_dedicated_thread(
    config: Arc<Config>,
    response_handler: ResponseHandler,
) -> Result<DatadogExporter, DatadogExporterInitError> {
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| DatadogExporterInitError::Runtime(SharedRuntimeError::RuntimeCreation(e)))?;
    let shared_runtime = Arc::new(BasicRuntime::from_handle(Arc::new(tokio_runtime)));

    let trace_exporter = build_trace_exporter(&config, &shared_runtime)
        .map_err(DatadogExporterInitError::TraceExporter)?;

    let buffer_config = TraceBufferConfig::default()
        .synchronous_export(config.trace_writer_synchronous_write())
        .synchronous_export_timeout(Some(config.trace_writer_synchronous_timeout()))
        .max_flush_interval(config.trace_writer_max_flush_interval());

    let otel_resource = Arc::new(ArcSwap::new(Arc::new(Resource::builder_empty().build())));
    let pending_spans: PendingSpans = Arc::new((Mutex::new(0_usize), Condvar::new()));

    let export = SpanDataExport {
        trace_exporter,
        otel_resource: Arc::clone(&otel_resource),
        cached_config: CachedConfig::new(&config),
        config: Arc::clone(&config),
        pending_spans: Arc::clone(&pending_spans),
    };

    let (trace_buffer, worker) =
        TraceBuffer::new(buffer_config, response_handler, Box::new(export));

    // `BasicRuntime` ignores `restart_on_fork`; pass `false` to make intent explicit. The worker
    // is torn down via `BasicRuntime::shutdown_async` during exporter shutdown.
    let _ = shared_runtime
        .spawn_worker(worker, false)
        .map_err(DatadogExporterInitError::Runtime)?;

    Ok(DatadogExporter {
        trace_buffer: Some(trace_buffer),
        shared_runtime: Some(shared_runtime),
        otel_resource,
        shutdown_rx: Mutex::new(None),
        pending_spans,
    })
}

fn increment_pending(pending: &PendingSpans, n: usize) {
    let (lock, _) = &**pending;
    if let Ok(mut count) = lock.lock() {
        *count = count.saturating_add(n);
    }
}

fn decrement_pending(pending: &PendingSpans, n: usize) {
    let (lock, cvar) = &**pending;
    if let Ok(mut count) = lock.lock() {
        *count = count.saturating_sub(n);
        if *count == 0 {
            cvar.notify_all();
        }
    }
}

fn build_trace_exporter(
    config: &Config,
    shared_runtime: &Arc<BasicRuntime>,
) -> Result<TraceExporter<NativeCapabilities, BasicRuntime>, TraceExporterError> {
    let mut builder = TraceExporterBuilder::<BasicRuntime>::new();
    builder
        .set_shared_runtime(Arc::clone(shared_runtime))
        .set_url(&config.trace_agent_url())
        .set_dogstatsd_url(&config.dogstatsd_agent_url())
        .set_tracer_version(config.tracer_version())
        .set_language(config.language())
        .set_language_version(config.language_version())
        .set_service(&config.service())
        .set_output_format(TraceExporterOutputFormat::V04)
        .enable_health_metrics()
        .enable_agent_rates_payload_version();

    if config.trace_partial_flush_enabled() {
        builder.set_client_computed_top_level();
    }
    if config.trace_stats_computation_enabled() {
        builder.enable_stats(Duration::from_secs(10));
    }
    if config.trace_stats_computation_experimental_client_obfuscation_enabled() {
        builder.enable_client_side_stats_obfuscation();
    }

    if let Some(env) = config.env() {
        builder.set_env(env);
    }
    if let Some(version) = config.version() {
        builder.set_app_version(version);
    }
    if config.telemetry_enabled() {
        builder.enable_telemetry(TelemetryConfig {
            heartbeat: (config.telemetry_heartbeat_interval() * 1000.0) as u64,
            runtime_id: Some(config.runtime_id().to_string()),
            debug_enabled: false,
        });
        builder.set_telemetry_instrumentation_sessions(
            telemetry_session::sessions_from_runtime_id(config.runtime_id()),
        );
    }

    builder.build::<NativeCapabilities>()
}

/// Tears the workers down on `shared_runtime` synchronously. Must be called from a thread that is
/// not already inside a tokio runtime — `BasicRuntime::block_on` would otherwise panic.
fn shutdown_basic_runtime(shared_runtime: &BasicRuntime) -> Result<(), SharedRuntimeError> {
    shared_runtime
        .block_on(shared_runtime.shutdown_async())
        .map_err(SharedRuntimeError::RuntimeCreation)
}

#[derive(Debug)]
struct SpanDataExport {
    trace_exporter: TraceExporter<NativeCapabilities, BasicRuntime>,
    otel_resource: Arc<ArcSwap<Resource>>,
    cached_config: CachedConfig,
    config: Arc<Config>,
    pending_spans: PendingSpans,
}

impl Export<BufferedSpan> for SpanDataExport {
    fn export_trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<BufferedSpan>>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<AgentResponse, TraceExporterError>> + Send + '_,
        >,
    > {
        // Account for every span we drained from the buffer, regardless of whether the export
        // ultimately succeeds — `send_chunk` already counted them on entry.
        let total_spans: usize = trace_chunks.iter().map(|c| c.len()).sum();
        Box::pin(async move {
            let resource = self.otel_resource.load_full();
            let dd_trace_chunks = trace_chunks
                .iter()
                .map(|chunk| {
                    ddtrace_transform::otel_trace_chunk_to_dd_trace_chunk(
                        &self.cached_config,
                        chunk.iter().map(|b| &b.0),
                        &resource,
                    )
                })
                .collect::<Vec<_>>();

            let services = dd_trace_chunks
                .iter()
                .flatten()
                .map(|s| s.service.as_str())
                .filter(|s| !s.is_empty() && *s != "otlpresourcenoservicename");
            self.config.add_extra_services(services);

            let result = self
                .trace_exporter
                .send_trace_chunks_async(dd_trace_chunks)
                .await;
            decrement_pending(&self.pending_spans, total_spans);
            result
        })
    }

    /// `Export::wait_ready` is the libdatadog hook called once by the trace-buffer worker before
    /// its first export. We wait here for the `/info` cache so the very first export's
    /// `check_agent_info` sees the cached response and transitions stats from `DisabledByAgent` to
    /// `Enabled`. Without it, fast tests can shut down before the info-fetcher's initial HTTP call
    /// completes, leaving stats disabled and the agent's tracestats snapshot expectations unmet.
    #[cfg(feature = "test-utils")]
    fn wait_ready(
        &mut self,
    ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        Box::pin(async {
            self.trace_exporter
                .wait_agent_info_ready(Duration::from_secs(5))
                .await
        })
    }
}

#[track_caller]
fn log_trace_exporter_error(e: &TraceExporterError) {
    use libdd_data_pipeline::trace_exporter::error::{
        AgentErrorKind, InternalErrorKind, ShutdownError,
    };

    use crate::{dd_debug, dd_error};

    match e {
        // Exceptional errors
        TraceExporterError::Builder(e) => {
            dd_error!("DatadogExporter: Export error: Builder error: {}", e);
        }
        TraceExporterError::Internal(InternalErrorKind::InvalidWorkerState(state)) => {
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
        TraceExporterError::Agent(AgentErrorKind::EmptyResponse) => {
            dd_debug!("DatadogExporter: Export error: Agent error: empty response");
        }
        TraceExporterError::Shutdown(ShutdownError::TimedOut(duration)) => {
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
