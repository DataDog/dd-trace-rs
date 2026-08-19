// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use libdd_shared_runtime::{BasicRuntime, SharedRuntime, SharedRuntimeError, Worker};

use crate::{core::telemetry, span_exporter::QueueMetricsFetcher, TraceRegistry};

const EMIT_INTERVAL: Duration = Duration::from_secs(10);

/// Periodically emits span/queue telemetry metrics.
///
/// Runs as a [`Worker`] on the runtime shared with the trace exporter (see
/// [`crate::span_processor`]). It has no independent shutdown: it is registered
/// via [`SharedRuntime::spawn_worker`] and torn down when the runtime's
/// `shutdown_async` runs during the exporter's shutdown — the same lifecycle as
/// the trace-export and Remote Config workers.
pub struct TelemetryMetricsCollector {
    registry: TraceRegistry,
    exporter_queue_metrics: QueueMetricsFetcher,
    /// Built lazily on the first [`Worker::trigger`] because `tokio::time`
    /// timers must be constructed inside a runtime context, and `start` runs on
    /// the caller's (non-runtime) thread. The first tick is one full interval
    /// out, so the first emission happens after `EMIT_INTERVAL` — matching the
    /// previous `recv_timeout` loop.
    interval: Option<tokio::time::Interval>,
}

impl std::fmt::Debug for TelemetryMetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetryMetricsCollector")
            .finish_non_exhaustive()
    }
}

impl TelemetryMetricsCollector {
    pub fn start(
        registry: TraceRegistry,
        exporter_queue_metrics: QueueMetricsFetcher,
        shared_runtime: &Arc<BasicRuntime>,
    ) -> Result<(), SharedRuntimeError> {
        let worker = Self {
            registry,
            exporter_queue_metrics,
            interval: None,
        };
        shared_runtime.spawn_worker(worker, false).map(|_handle| ())
    }

    fn emit_metrics(&mut self) {
        use telemetry::TelemetryMetric::*;
        let registry_metrics = self.registry.get_metrics();
        let exporter_queue_metrics = self.exporter_queue_metrics.get_metrics();

        telemetry::add_points([
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

#[async_trait]
impl Worker for TelemetryMetricsCollector {
    async fn run(&mut self) {
        self.emit_metrics();
    }

    async fn trigger(&mut self) {
        let interval = self.interval.get_or_insert_with(|| {
            // First tick one interval out so the first emission is delayed by
            // `EMIT_INTERVAL`, matching the previous `recv_timeout` loop.
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + EMIT_INTERVAL,
                EMIT_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval
        });
        interval.tick().await;
    }
}
