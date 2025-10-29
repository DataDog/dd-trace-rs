// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use dd_trace::utils::{ShutdownSignaler, WorkerError, WorkerHandle};

use crate::TraceRegistry;

pub struct TelemetryMetricsCollector {
    registry: TraceRegistry,
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
    pub fn start(registry: TraceRegistry) -> TelemetryMetricsCollectorHandle {
        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::sync_channel(1);
        let shutdown_finished = ShutdownSignaler::new();
        let worker = Self {
            registry,
            shutdown_rx,
            shutdown_finished: shutdown_finished.clone(),
        };
        let handle = std::thread::spawn(|| worker.run());
        TelemetryMetricsCollectorHandle {
            shutdown_tx,
            worker_handle: WorkerHandle::new(shutdown_finished, handle),
        }
    }

    fn run(mut self) {
        loop {
            match self.shutdown_rx.recv_timeout(Duration::from_secs(10)) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) | Ok(()) => return,
            };
            self.emit_metrics();
        }
    }

    fn emit_metrics(&mut self) {
        use dd_trace::telemetry::TelemetryMetric::*;
        let stats = self.registry.get_stats();
        dd_trace::telemetry::add_point(stats.spans_created as f64, SpansCreated);
        dd_trace::telemetry::add_point(stats.spans_finished as f64, SpansFinished);
        dd_trace::telemetry::add_point(stats.spans_flushed as f64, SpansEnqueuedForSerialization);
        dd_trace::telemetry::add_point(stats.trace_segments_created as f64, TraceSegmentsCreated);
        dd_trace::telemetry::add_point(stats.trace_segments_closed as f64, TraceSegmentsClosed);
    }
}
