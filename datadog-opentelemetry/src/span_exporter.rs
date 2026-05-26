// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{pin::Pin, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use libdd_data_pipeline::{
    trace_buffer::{Export, TraceBuffer, TraceBufferConfig, TraceBufferError, TraceChunk},
    trace_exporter::{
        agent_response::AgentResponse, error::TraceExporterError, TelemetryConfig,
        TraceExporterOutputFormat,
    },
};
use libdd_shared_runtime::SharedRuntime;
use opentelemetry_sdk::{trace::SpanData, Resource};

use crate::{configuration::Config, dd_debug, dd_error, ddtrace_transform, mappings::CachedConfig};

pub type QueueMetricsFetcher = libdd_data_pipeline::trace_buffer::QueueMetricsFetcher<SpanData>;

pub struct DatadogExporter {
    trace_buffer: TraceBuffer<SpanData>,
    runtime: Arc<SharedRuntime>,
    otel_resource: Arc<ArcSwap<Resource>>,
}

impl DatadogExporter {
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: Arc<Config>,
        agent_response_handler: Option<Box<dyn for<'a> Fn(&'a str) + Send + Sync>>,
    ) -> Self {
        let otel_resource = Arc::new(ArcSwap::new(Arc::new(Resource::builder_empty().build())));

        // Pick the runtime backing based on whether we were constructed from inside an
        // existing tokio context. If we are (the common case for a Rust web service
        // booting up dd-trace-rs from its main `#[tokio::main]`), borrow that host
        // runtime instead of spinning up a second one. Borrowed mode gives up
        // fork-safety in exchange for letting Drop/shutdown work cleanly from a host
        // worker thread without `block_on` — see the borrowed-runtime work in
        // `libdd-shared-runtime`.
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(handle) => Arc::new(SharedRuntime::from_handle(handle)),
            Err(_) => Arc::new(
                SharedRuntime::new().expect("failed to create SharedRuntime for trace exporter"),
            ),
        };

        let mut builder = libdd_data_pipeline::trace_exporter::TraceExporterBuilder::default();
        builder
            .set_url(&config.trace_agent_url())
            .set_dogstatsd_url(&config.dogstatsd_agent_url())
            .set_tracer_version(config.tracer_version())
            .set_language(config.language())
            .set_language_version(config.language_version())
            .set_service(&config.service())
            .set_output_format(TraceExporterOutputFormat::V04)
            .set_shared_runtime(runtime.clone())
            .enable_health_metrics()
            .enable_agent_rates_payload_version();

        if config.trace_partial_flush_enabled() {
            builder.set_client_computed_top_level();
        }
        if config.trace_stats_computation_enabled() {
            builder.enable_stats(Duration::from_secs(10));
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
        }

        // Drive the async builder to completion. The future's only suspension point is
        // a single non-blocking mpsc `send` into a freshly-created telemetry-worker
        // channel, which is always Ready on first poll. We deliberately use
        // [`poll_to_completion`] instead of `SharedRuntime::block_on` (which errors in
        // borrowed mode) or `tokio::Handle::block_on` (which panics from inside a tokio
        // worker thread). See [`poll_to_completion`]'s docs for the contract.
        let trace_exporter = poll_to_completion(
            builder.build_async::<libdd_capabilities_impl::NativeCapabilities>(),
        )
        .expect("failed to build TraceExporter");

        // Create the TraceBuffer + worker
        let (trace_buffer, worker) = TraceBuffer::new(
            TraceBufferConfig::new()
                .synchronous_export(config.trace_writer_synchronous_write())
                .synchronous_export_timeout(Some(config.trace_writer_synchronous_timeout()))
                .max_flush_interval(config.trace_writer_max_flush_interval()),
            // Build the response handler that bridges the old callback API
            Box::new(
                move |result: Result<AgentResponse, TraceExporterError>| match result {
                    Ok(AgentResponse::Unchanged) => {}
                    Ok(AgentResponse::Changed { body }) => {
                        if let Some(ref handler) = agent_response_handler {
                            (handler)(&body);
                        }
                    }
                    Err(e) => log_trace_exporter_error(&e),
                },
            ),
            // Build the export operation
            Box::new(MapperExporter {
                trace_exporter,
                otel_resource: arc_swap::Cache::new(otel_resource.clone()),
                cached_config: CachedConfig::new(&config),
                config: config.clone(),
            }),
        );

        let _ = runtime
            .spawn_worker(worker, true)
            .expect("failed to spawn TraceExporterWorker");

        DatadogExporter {
            trace_buffer,
            runtime,
            otel_resource,
        }
    }

    pub fn queue_metrics(&self) -> QueueMetricsFetcher {
        self.trace_buffer.queue_metrics()
    }

    pub fn send_chunk(&self, span_data: Vec<SpanData>) -> Result<(), TraceBufferError> {
        self.trace_buffer.send_chunk(span_data)
    }

    pub fn force_flush(&self) -> Result<(), TraceBufferError> {
        self.trace_buffer.force_flush()
    }

    /// Shut down the trace exporter runtime and wait for the worker to finish.
    ///
    /// Safe to call from any sync context, including from inside the host tokio runtime
    /// when this exporter was constructed in borrowed mode. Internally:
    /// 1. Flushes buffered spans via [`TraceBuffer::flush_and_wait`].
    /// 2. Cancels every worker on the underlying [`SharedRuntime`] via
    ///    [`SharedRuntime::trigger_shutdown_signal`] (non-blocking) and waits for each
    ///    to finish via [`SharedRuntime::wait_shutdown_done`].
    /// 3. Waits for the trace-buffer worker's shutdown flag via
    ///    [`TraceBuffer::wait_shutdown_done`].
    ///
    /// # Borrowed-mode threading requirements
    /// When [`SharedRuntime`] is borrowed (i.e. constructed in [`Self::new`] from inside
    /// a `tokio::runtime::Handle::try_current`), the worker-shutdown tasks must be
    /// driven by the host runtime *while* this function is parked on its Condvars.
    /// That only works if the host has more than one worker thread:
    ///
    /// - **`flavor = "multi_thread"` (default for `#[tokio::main]`)**: we detach the
    ///   calling worker via [`tokio::task::block_in_place`] so the remaining workers
    ///   drive the shutdown tasks. This is the supported production path.
    /// - **`flavor = "current_thread"` (default for `#[tokio::test]`)**: the only
    ///   worker is the one we're about to park, so the shutdown tasks would never get
    ///   to run. We detect this and fall back to a best-effort
    ///   `trigger_shutdown_signal` + bounded `wait` strategy that returns within
    ///   `timeout` even if workers haven't quiesced. Callers running in this mode
    ///   should prefer the multi-thread test flavor for deterministic shutdown.
    pub fn shutdown(&self, timeout: Duration) -> Result<(), TraceBufferError> {
        let deadline = std::time::Instant::now() + timeout;
        let remaining = || deadline.saturating_duration_since(std::time::Instant::now());

        // Flush any buffered spans synchronously first. This guarantees the trace exporter
        // has a chance to run `check_agent_info` (which starts the stats worker on the still
        // alive SharedRuntime) before we tear the workers down. Without this, fast-finishing
        // applications would shut the workers down before the stats worker ever ran, dropping
        // the stats payload and breaking expectations downstream.
        let flush_result = if self.runtime.is_borrowed() && tokio_is_multi_thread() {
            // Detach the current tokio worker so the host's other workers can drive the
            // trace-buffer worker's flush while we park on the Condvar inside
            // `flush_and_wait`. Without this, the Condvar wait would block the only
            // tokio worker thread available to make progress.
            tokio::task::block_in_place(|| self.trace_buffer.flush_and_wait(remaining()))
        } else {
            self.trace_buffer.flush_and_wait(remaining())
        };
        match flush_result {
            Ok(()) | Err(TraceBufferError::AlreadyShutdown) => {}
            Err(e) => {
                dd_debug!(
                    "DatadogExporter.shutdown message='flush_and_wait before shutdown failed' error='{e:?}'"
                );
            }
        }

        // Trigger non-blocking cancellation for every worker.
        if let Err(e) = self.runtime.trigger_shutdown_signal() {
            dd_debug!(
                "DatadogExporter.shutdown message='trigger_shutdown_signal failed' error='{e:?}'"
            );
        }

        // Wait for the spawned shutdown tasks to complete. Inside a multi-thread host
        // runtime, escape the worker via `block_in_place` so the Condvar wait doesn't
        // starve the executor. Inside a current-thread host (typical for
        // `#[tokio::test]`), waiting would deadlock — return early with whatever
        // status `wait_shutdown_done` reports without parking.
        let runtime_wait_result = if self.runtime.is_borrowed() && tokio_is_multi_thread() {
            tokio::task::block_in_place(|| self.runtime.wait_shutdown_done(remaining()))
        } else if self.runtime.is_borrowed() {
            // Best-effort on current_thread host — see method-level docs.
            dd_debug!(
                "DatadogExporter.shutdown message='current_thread host runtime detected — skipping Condvar wait to avoid deadlock'"
            );
            Ok(())
        } else {
            self.runtime.wait_shutdown_done(remaining())
        };
        runtime_wait_result.map_err(|_| TraceBufferError::TimedOut(timeout))?;

        let trace_buffer_wait = if self.runtime.is_borrowed() && tokio_is_multi_thread() {
            tokio::task::block_in_place(|| self.trace_buffer.wait_shutdown_done(remaining()))
        } else if self.runtime.is_borrowed() {
            Ok(())
        } else {
            self.trace_buffer.wait_shutdown_done(remaining())
        };
        trace_buffer_wait.map_err(|e| match e {
            // Re-base any TimedOut to the user-facing total budget so the caller sees
            // the value they passed in, not the residual we ended up with.
            TraceBufferError::TimedOut(_) => TraceBufferError::TimedOut(timeout),
            other => other,
        })
    }

    pub fn set_resource(&self, r: Resource) {
        self.otel_resource.store(Arc::new(r));
    }
}

/// Fallback shutdown timeout used by [`Drop`] when the caller forgot to invoke
/// [`DatadogExporter::shutdown`] explicitly. Matches the `trace_exporter_shutdown_timeout`
/// default used by the previous (pre-libdatadog) `AsyncExporterConfig`.
const DROP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

impl Drop for DatadogExporter {
    /// Best-effort shutdown so callers that forget to invoke
    /// [`DatadogExporter::shutdown`] don't leak workers or lose buffered spans.
    ///
    /// Safe to invoke from inside a tokio runtime: [`Self::shutdown`] uses
    /// Condvar-based waits (via [`SharedRuntime::trigger_shutdown_signal`] +
    /// [`SharedRuntime::wait_shutdown_done`] and [`TraceBuffer::wait_shutdown_done`])
    /// instead of `block_on`, so there's no risk of "Cannot start a runtime from
    /// within a runtime" panics from a host worker thread.
    ///
    /// `shutdown` is idempotent — a prior explicit call is a no-op the second time:
    /// `flush_and_wait` and `wait_shutdown_done` early-return on `AlreadyShutdown`,
    /// and a second `trigger_shutdown_signal` snapshots an already-empty worker list.
    fn drop(&mut self) {
        if let Err(e) = self.shutdown(DROP_SHUTDOWN_TIMEOUT) {
            dd_debug!("DatadogExporter.drop message='fallback shutdown failed' error='{e:?}'");
        }
    }
}

/// Synchronously drive a future to completion without engaging any tokio runtime.
///
/// `DatadogExporter::new` calls this to run [`TraceExporterBuilder::build_async`] from
/// a sync constructor that may itself be invoked from inside a host tokio worker
/// thread. The natural choices both fail in that situation:
/// - [`SharedRuntime::block_on`] returns an error in borrowed mode (where the borrowed
///   runtime is exactly the one we're already running on).
/// - [`tokio::runtime::Handle::block_on`] / a freshly-built [`tokio::runtime::Runtime`]
///   panic with "Cannot start a runtime from within a runtime".
///
/// # Contract
/// This helper polls the future on the current thread and parks the thread between
/// polls. It is only sound when the future's `.await` points never park on a tokio
/// I/O / timer source — otherwise nothing would wake the parked thread. The
/// `build_async` future qualifies: its only suspension point is a single non-blocking
/// `mpsc::Sender::send` into a freshly-spawned channel that always has capacity, so
/// the future polls to `Ready` on the first iteration.
/// Whether the current tokio runtime is configured with more than one worker thread.
///
/// Returns `false` when called outside any tokio runtime, or from inside a current-thread
/// runtime (`#[tokio::main(flavor = "current_thread")]`, default `#[tokio::test]`).
/// Returns `true` when called from inside a multi-thread runtime
/// (`#[tokio::main(flavor = "multi_thread")]`, default `#[tokio::main]`).
///
/// Used by [`DatadogExporter::shutdown`] to decide whether it is safe to escape the
/// current tokio worker via [`tokio::task::block_in_place`] before parking on the
/// shutdown Condvars. `block_in_place` panics in a current-thread runtime, so we must
/// check first.
fn tokio_is_multi_thread() -> bool {
    use tokio::runtime::RuntimeFlavor;
    match tokio::runtime::Handle::try_current() {
        // Any flavor other than CurrentThread is multi-worker for our purposes
        // (`MultiThread`, plus unstable variants like `MultiThreadAlt`). Match
        // negatively so future tokio versions that add more flavors don't break
        // borrowed-mode shutdown.
        Ok(handle) => !matches!(handle.runtime_flavor(), RuntimeFlavor::CurrentThread),
        Err(_) => false,
    }
}

fn poll_to_completion<F: std::future::Future>(future: F) -> F::Output {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread;

    struct ThreadWaker(thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker: Waker = Arc::new(ThreadWaker(thread::current())).into();
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(future);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}

struct MapperExporter {
    trace_exporter: libdd_data_pipeline::trace_exporter::TraceExporter<
        libdd_capabilities_impl::NativeCapabilities,
    >,
    otel_resource: arc_swap::cache::Cache<
        Arc<arc_swap::ArcSwap<opentelemetry_sdk::Resource>>,
        Arc<opentelemetry_sdk::Resource>,
    >,
    cached_config: CachedConfig,
    config: Arc<Config>,
}

impl std::fmt::Debug for MapperExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapperExporter").finish()
    }
}

impl Export<SpanData> for MapperExporter {
    fn export_trace_chunks(
        &mut self,
        trace_chunks: Vec<TraceChunk<SpanData>>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<AgentResponse, TraceExporterError>> + Send + '_,
        >,
    > {
        // Snapshot what we need from &mut self up-front. `otel_resource.load()` requires
        // &mut self, so we cannot do it inside the async block while also holding other
        // &self borrows. Cloning the `Arc<Resource>` is cheap (just a refcount bump).
        let resource = self.otel_resource.load().clone();
        let trace_exporter = &self.trace_exporter;
        let cached_config = &self.cached_config;
        let config = self.config.clone();

        // Do the OTel->DD conversion inside the async block so the resulting
        // `Vec<DdSpan<'_>>` (which borrows from `trace_chunks`) is owned by the future
        // alongside `trace_chunks` itself — no borrows escape the future.
        //
        // Use the async send: the buffer worker awaits this future from inside the
        // SharedRuntime's tokio scheduler, so the synchronous `send_trace_chunks` would
        // attempt a `block_on` on the same runtime and panic.
        Box::pin(async move {
            let dd_chunks = trace_chunks
                .iter()
                .map(|chunk| -> Vec<_> {
                    ddtrace_transform::otel_trace_chunk_to_dd_trace_chunk(
                        cached_config,
                        chunk,
                        &resource,
                    )
                })
                .collect::<Vec<_>>();

            let services = dd_chunks
                .iter()
                .flatten()
                .map(|s| s.service.as_str())
                .filter(|s| !s.is_empty() && *s != "otlpresourcenoservicename");
            config.add_extra_services(services);

            trace_exporter.send_trace_chunks_async(dd_chunks).await
        })
    }

    /// Test-only hook: wait for the agent info fetcher to populate the agent capabilities so
    /// that downstream behaviour (in particular client-side stats and the `_top_level` metric)
    /// is active before the worker processes its first batch. Without this, snapshot tests
    /// that produce spans and shutdown immediately race with the agent_info fetch and end up
    /// asserting against spans missing stats-derived metrics.
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
    use libdd_data_pipeline::trace_exporter::error;
    match e {
        // Exceptional errors
        TraceExporterError::Builder(e) => {
            dd_error!("DatadogExporter: Export error: Builder error: {}", e);
        }
        TraceExporterError::Internal(error::InternalErrorKind::InvalidWorkerState(state)) => {
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
        TraceExporterError::Agent(error::AgentErrorKind::EmptyResponse) => {
            dd_debug!("DatadogExporter: Export error: Agent error: empty response");
        }
        TraceExporterError::Shutdown(error::ShutdownError::TimedOut(duration)) => {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::DatadogExporter;
    use crate::configuration::Config;

    /// Regression coverage for the borrowed-runtime path: dropping a `DatadogExporter`
    /// from inside a tokio runtime must not panic, and the underlying `SharedRuntime`
    /// must have been constructed in borrowed mode so that its shutdown uses the
    /// Condvar-based `wait_shutdown_done` rather than a `block_on` that would deadlock
    /// or panic on a host worker thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_drop_inside_tokio_runtime() {
        let mut cfg = Config::builder();
        cfg.set_trace_agent_url("http://127.0.0.1:1".to_string());
        let cfg = Arc::new(cfg.build());

        let exporter = DatadogExporter::new(cfg, None);
        // Inside a `#[tokio::test]` we *must* have picked borrowed mode in `new`. If
        // we hadn't, Drop teardown would hit `SharedRuntime::block_on` and panic with
        // "Cannot start a runtime from within a runtime" on the host worker thread.
        assert!(
            exporter.runtime.is_borrowed(),
            "DatadogExporter::new should pick borrowed mode when constructed from inside tokio"
        );
        drop(exporter);
    }

    /// Same as above, but exercises the idempotency claim in the Drop doc-comment:
    /// calling `shutdown` explicitly and *then* letting Drop run should not panic and
    /// should be a fast no-op for the second teardown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_drop_after_explicit_shutdown_is_noop() {
        let mut cfg = Config::builder();
        cfg.set_trace_agent_url("http://127.0.0.1:1".to_string());
        let cfg = Arc::new(cfg.build());

        let exporter = DatadogExporter::new(cfg, None);
        assert!(exporter.runtime.is_borrowed());
        let _ = exporter.shutdown(std::time::Duration::from_millis(500));
        drop(exporter);
    }

    /// Outside of any tokio context, `DatadogExporter::new` should fall back to creating
    /// an owned [`SharedRuntime`] — that's the path FFI consumers and test/CLI binaries
    /// hit and the one that preserves the fork-safety guarantees libdatadog gives us.
    #[test]
    fn test_new_outside_tokio_picks_owned_runtime() {
        let mut cfg = Config::builder();
        cfg.set_trace_agent_url("http://127.0.0.1:1".to_string());
        let cfg = Arc::new(cfg.build());

        let exporter = DatadogExporter::new(cfg, None);
        assert!(
            !exporter.runtime.is_borrowed(),
            "DatadogExporter::new should pick owned mode outside any tokio context"
        );
        // Tear down explicitly so the Drop path is exercised too.
        let _ = exporter.shutdown(std::time::Duration::from_secs(1));
    }
}
