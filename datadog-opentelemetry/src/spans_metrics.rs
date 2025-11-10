// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use dd_trace::{
    utils::{ShutdownSignaler, WorkerError, WorkerHandle},
    Config,
};

use crate::{span_exporter::QueueMetricsFetcher, TraceRegistry};

pub struct TelemetryMetricsCollector {
    config: Arc<Config>,
    registry: TraceRegistry,
    exporter_queue_metrics: QueueMetricsFetcher,
    shutdown_rx: std::sync::mpsc::Receiver<()>,
    shutdown_finished: Arc<dd_trace::utils::ShutdownSignaler>,
}

pub struct TelemetryMetricsCollectorHandle {
    shutdown_tx: std::sync::mpsc::SyncSender<()>,
    worker_handle: dd_trace::utils::WorkerHandle,
}

impl TelemetryMetricsCollectorHandle {
    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.try_send(());
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), WorkerError> {
        self.worker_handle.wait_for_shutdown(timeout)
    }
}

impl Drop for TelemetryMetricsCollector {
    fn drop(&mut self) {
        self.shutdown_finished.signal_shutdown();
    }
}

impl TelemetryMetricsCollector {
    pub fn start(
        config: Arc<Config>,
        registry: TraceRegistry,
        exporter_queue_metrics: QueueMetricsFetcher,
    ) -> TelemetryMetricsCollectorHandle {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel(1);
        let shutdown_finished = ShutdownSignaler::new();
        let worker = Self {
            config,
            registry,
            shutdown_rx,
            shutdown_finished: shutdown_finished.clone(),
            exporter_queue_metrics,
        };
        let handle = std::thread::spawn(dd_trace::log::with_local_logger(|| worker.run()));
        TelemetryMetricsCollectorHandle {
            shutdown_tx,
            worker_handle: WorkerHandle::new(shutdown_finished, handle),
        }
    }

    fn run(mut self) {
        let interval;
        #[cfg(feature = "test-utils")]
        {
            interval = self.config.__internal_span_metrics_interval();
        }
        #[cfg(not(feature = "test-utils"))]
        {
            interval = Duration::from_secs(10);
        }
        #[allow(clippy::while_let_loop)]
        loop {
            match self.shutdown_rx.recv_timeout(interval) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) | Ok(()) => break,
            };
            self.emit_metrics();
            if self.config.trace_debug_open_spans() {
                self.warn_maybe_abandoned_traces();
            }
        }
        if self.config.trace_debug_open_spans() {
            self.warn_shutdown_abandoned_traces();
        }
    }

    fn warn_shutdown_abandoned_traces(&self) {
        for t in self.registry.iter_lost_traces().take(100) {
            // Log at most 100 traces
            let open_spans_details = t
                .open_span_details
                .iter()
                .map(|s| {
                    format!(
                        "{{span_id:{:x} name:{} age:{}ms}}",
                        s.span_id,
                        s.name,
                        std::time::Instant::now()
                            .duration_since(s.start_ts)
                            .as_millis()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");

            dd_trace::dd_warn!(
                    "lost trace not finished during shutdown trace_id={} root_name={} age={}ms open_spans={} open_span_details=[{}]",
                    t.tid,
                    t.root_span_name.as_str(),
                    t.age.as_millis(),
                    t.open_spans,
                    open_spans_details
                )
        }
    }

    fn warn_maybe_abandoned_traces(&self) {
        let min_age = self.config.trace_debug_open_spans_timeout();
        // Log at most 100 traces
        for t in self.registry.iter_old_traces(min_age).take(100) {
            let open_spans_details = t
                .open_span_details
                .iter()
                .map(|s| {
                    format!(
                        "{{span_id:{:x} name:{} age:{}ms}}",
                        s.span_id,
                        s.name,
                        std::time::Instant::now()
                            .duration_since(s.start_ts)
                            .as_millis()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");

            dd_trace::dd_warn!(
                "possibly abandoned trace trace_id={} root_name={} age={}ms open_spans={} open_span_details=[{}]",
                t.tid,
                t.root_span_name.as_str(),
                t.age.as_millis(),
                t.open_spans,
                open_spans_details
            )
        }
    }

    fn emit_metrics(&mut self) {
        use dd_trace::telemetry::TelemetryMetric::*;
        let registry_metrics = self.registry.get_metrics();
        let exporter_queue_metrics = self.exporter_queue_metrics.get_metrics();

        dd_trace::telemetry::add_points([
            (registry_metrics.spans_created as f64, SpansCreated),
            (registry_metrics.spans_finished as f64, SpansFinished),
            (
                registry_metrics.trace_segments_created as f64,
                TraceSegmentsCreated,
            ),
            (
                registry_metrics.trace_segments_closed as f64,
                TraceSegmentsClosed,
            ),
            (
                registry_metrics.trace_partial_flush_count as f64,
                TracePartialFlushCount,
            ),
            (
                exporter_queue_metrics.spans_queued as f64,
                SpansEnqueuedForSerialization,
            ),
            (
                exporter_queue_metrics.spans_dropped_full_buffer as f64,
                SpansDroppedBufferFull,
            ),
        ]);
    }
}
