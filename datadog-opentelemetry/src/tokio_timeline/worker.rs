// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Background worker thread for timeline data collection and upload.

use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use crossbeam_channel::Receiver;

use crate::core::configuration::Config;
use crate::tokio_timeline::buffer::{EventBuffer, OwnedEvent};
use crate::tokio_timeline::config::{TimelineConfig, TimelineFormat};
use crate::tokio_timeline::serializer::go_trace::GoTraceSerializer;
use crate::tokio_timeline::serializer::pprof_timeline::PprofTimelineSerializer;
use crate::tokio_timeline::serializer::{SerializedTimeline, TimelineSerializer};
use crate::tokio_timeline::uploader::TimelineUploader;
use crate::{dd_debug, dd_error};

/// Shared state between the sender and worker thread.
struct SharedState {
    /// Whether a flush has been requested.
    flush_requested: bool,
    /// Whether shutdown has been requested.
    shutdown_requested: bool,
    /// Whether the worker has completed shutdown.
    has_shutdown: bool,
}

/// Coordination primitive for worker thread.
struct Waiter {
    state: Mutex<SharedState>,
    condvar: Condvar,
}

impl Waiter {
    fn new() -> Self {
        Self {
            state: Mutex::new(SharedState {
                flush_requested: false,
                shutdown_requested: false,
                has_shutdown: false,
            }),
            condvar: Condvar::new(),
        }
    }

    fn notify_all(&self, guard: MutexGuard<'_, SharedState>) {
        drop(guard);
        self.condvar.notify_all();
    }
}

/// Handle for controlling the timeline worker.
pub struct TimelineWorkerHandle {
    /// Waiter for coordination.
    waiter: Arc<Waiter>,
    /// Worker thread handle.
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl TimelineWorkerHandle {
    /// Requests the worker to flush its current buffer.
    pub fn flush(&self) {
        if let Ok(mut state) = self.waiter.state.lock() {
            state.flush_requested = true;
            self.waiter.notify_all(state);
        }
    }

    /// Requests the worker to shut down gracefully.
    pub fn shutdown(&self, timeout: Duration) -> Result<(), ShutdownError> {
        // Request shutdown
        {
            let mut state = self
                .waiter
                .state
                .lock()
                .map_err(|_| ShutdownError::MutexPoisoned)?;
            state.shutdown_requested = true;
            self.waiter.notify_all(state);
        }

        // Wait for shutdown to complete
        {
            let state = self
                .waiter
                .state
                .lock()
                .map_err(|_| ShutdownError::MutexPoisoned)?;
            let (_guard, result) = self
                .waiter
                .condvar
                .wait_timeout_while(state, timeout, |s| !s.has_shutdown)
                .map_err(|_| ShutdownError::MutexPoisoned)?;

            if result.timed_out() {
                return Err(ShutdownError::TimedOut(timeout));
            }
        }

        // Join the thread
        let handle = self
            .handle
            .lock()
            .map_err(|_| ShutdownError::MutexPoisoned)?
            .take();

        if let Some(h) = handle {
            h.join().map_err(|_| ShutdownError::ThreadPanic)?;
        }

        Ok(())
    }
}

/// Error that can occur during shutdown.
#[derive(Debug)]
pub enum ShutdownError {
    /// Shutdown timed out.
    TimedOut(Duration),
    /// A mutex was poisoned.
    MutexPoisoned,
    /// The worker thread panicked.
    ThreadPanic,
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownError::TimedOut(d) => write!(f, "shutdown timed out after {:?}", d),
            ShutdownError::MutexPoisoned => write!(f, "mutex poisoned"),
            ShutdownError::ThreadPanic => write!(f, "worker thread panicked"),
        }
    }
}

impl std::error::Error for ShutdownError {}

/// Spawns the timeline worker thread.
pub fn spawn_worker(
    config: Arc<Config>,
    timeline_config: TimelineConfig,
    receiver: Receiver<OwnedEvent>,
) -> TimelineWorkerHandle {
    let waiter = Arc::new(Waiter::new());
    let waiter_clone = Arc::clone(&waiter);

    let handle = thread::spawn(move || {
        let worker = TimelineWorker::new(config, timeline_config, receiver, waiter_clone);
        worker.run();
    });

    TimelineWorkerHandle {
        waiter,
        handle: Mutex::new(Some(handle)),
    }
}

/// Background worker that collects events and uploads them periodically.
struct TimelineWorker {
    /// Timeline-specific configuration.
    timeline_config: TimelineConfig,
    /// Channel receiver for events.
    receiver: Receiver<OwnedEvent>,
    /// Event buffer.
    buffer: EventBuffer,
    /// Coordination waiter.
    waiter: Arc<Waiter>,
    /// Uploader for sending data to Datadog.
    uploader: TimelineUploader,
    /// Go trace serializer.
    go_serializer: GoTraceSerializer,
    /// pprof serializer.
    pprof_serializer: PprofTimelineSerializer,
    /// Last flush time.
    last_flush: Instant,
}

impl TimelineWorker {
    fn new(
        config: Arc<Config>,
        timeline_config: TimelineConfig,
        receiver: Receiver<OwnedEvent>,
        waiter: Arc<Waiter>,
    ) -> Self {
        let buffer = EventBuffer::new(
            timeline_config.max_buffer_size,
            timeline_config.max_buffered_events,
        );
        let uploader = TimelineUploader::new(Arc::clone(&config));

        Self {
            timeline_config,
            receiver,
            buffer,
            waiter,
            uploader,
            go_serializer: GoTraceSerializer::new(),
            pprof_serializer: PprofTimelineSerializer::new(),
            last_flush: Instant::now(),
        }
    }

    fn run(mut self) {
        loop {
            // Check for shutdown or flush request
            let should_shutdown = {
                let state = match self.waiter.state.lock() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                state.shutdown_requested
            };

            if should_shutdown {
                // Final flush before shutdown
                self.flush();
                break;
            }

            // Calculate time until next scheduled flush
            let elapsed = self.last_flush.elapsed();
            let remaining = self.timeline_config.upload_interval.saturating_sub(elapsed);

            // Try to receive events with timeout
            match self
                .receiver
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(event) => {
                    let should_flush = self.buffer.push(event);
                    if should_flush {
                        self.flush();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    // Check if it's time for a scheduled flush
                    if self.last_flush.elapsed() >= self.timeline_config.upload_interval {
                        self.flush();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    // Channel closed, flush and exit
                    self.flush();
                    break;
                }
            }

            // Check for explicit flush request
            {
                let mut state = match self.waiter.state.lock() {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if state.flush_requested {
                    state.flush_requested = false;
                    drop(state);
                    self.flush();
                }
            }
        }

        // Signal shutdown complete
        if let Ok(mut state) = self.waiter.state.lock() {
            state.has_shutdown = true;
            self.waiter.notify_all(state);
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            self.last_flush = Instant::now();
            return;
        }

        let (events, batch_start) = self.buffer.drain();
        let batch_end = SystemTime::now();
        self.last_flush = Instant::now();

        // Serialize based on format
        let timelines = self.serialize_events(&events, batch_start, batch_end);

        if timelines.is_empty() {
            return;
        }

        // Debug: save trace/profile to file for analysis
        for timeline in &timelines {
            let path = format!("/tmp/generated_{}", timeline.filename);
            let _ = std::fs::write(&path, &timeline.data);
            eprintln!("[debug] Saved {} bytes to {}", timeline.data.len(), path);
        }

        // Upload
        if let Err(e) = self.uploader.upload(&timelines, batch_start, batch_end) {
            eprintln!("[error] Timeline upload failed: {}", e);
        } else {
            eprintln!(
                "[debug] Timeline uploaded: {} events, {} bytes",
                events.len(),
                timelines.iter().map(|t| t.data.len()).sum::<usize>()
            );
        }
    }

    fn serialize_events(
        &mut self,
        events: &[OwnedEvent],
        batch_start: SystemTime,
        batch_end: SystemTime,
    ) -> Vec<SerializedTimeline> {
        let mut timelines = Vec::new();

        match self.timeline_config.format {
            TimelineFormat::GoTrace => {
                if let Ok(timeline) = self.go_serializer.serialize(events, batch_start, batch_end) {
                    timelines.push(timeline);
                }
            }
            TimelineFormat::Pprof => {
                if let Ok(timeline) =
                    self.pprof_serializer
                        .serialize(events, batch_start, batch_end)
                {
                    timelines.push(timeline);
                }
            }
            TimelineFormat::Both => {
                if let Ok(timeline) = self.go_serializer.serialize(events, batch_start, batch_end) {
                    timelines.push(timeline);
                }
                if let Ok(timeline) =
                    self.pprof_serializer
                        .serialize(events, batch_start, batch_end)
                {
                    timelines.push(timeline);
                }
            }
        }

        timelines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waiter_shutdown_signal() {
        let waiter = Waiter::new();

        {
            let mut state = waiter.state.lock().unwrap();
            assert!(!state.shutdown_requested);
            assert!(!state.has_shutdown);
            state.shutdown_requested = true;
        }

        {
            let state = waiter.state.lock().unwrap();
            assert!(state.shutdown_requested);
        }
    }

    #[test]
    fn test_spawn_and_shutdown() {
        let config = Arc::new(Config::builder().build());
        let timeline_config = TimelineConfig::builder()
            .upload_interval(Duration::from_secs(1))
            .build();

        let (sender, receiver) = crossbeam_channel::unbounded();
        let handle = spawn_worker(config, timeline_config, receiver);

        // Drop sender to signal channel close
        drop(sender);

        // Should shut down cleanly
        let result = handle.shutdown(Duration::from_secs(5));
        assert!(result.is_ok());
    }

    #[test]
    fn test_spawn_with_events() {
        let config = Arc::new(Config::builder().build());
        let timeline_config = TimelineConfig::builder()
            .upload_interval(Duration::from_millis(100))
            .max_buffered_events(10)
            .build();

        let (sender, receiver) = crossbeam_channel::unbounded();
        let handle = spawn_worker(config, timeline_config, receiver);

        // Send some events
        for i in 0..5 {
            sender
                .send(OwnedEvent::PollEnd {
                    timestamp_nanos: i * 1000,
                    worker_id: 0,
                })
                .ok();
        }

        // Give worker time to process
        std::thread::sleep(Duration::from_millis(50));

        // Drop sender and shutdown
        drop(sender);
        let result = handle.shutdown(Duration::from_secs(5));
        assert!(result.is_ok());
    }
}
