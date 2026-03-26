// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Tokio runtime timeline telemetry for Datadog.
//!
//! This module provides integration with `dial9-tokio-telemetry` to capture
//! Tokio runtime events and upload them to Datadog's profiling endpoint for
//! visualization in the Timeline View.
//!
//! # Requirements
//!
//! This feature requires **Tokio's unstable APIs**. You must compile your project
//! with the `tokio_unstable` cfg flag:
//!
//! ```bash
//! RUSTFLAGS="--cfg tokio_unstable" cargo build --features tokio-timeline
//! ```
//!
//! Or add to `.cargo/config.toml`:
//!
//! ```toml
//! [build]
//! rustflags = ["--cfg", "tokio_unstable"]
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig, TimelineFormat};
//! use dial9_tokio_telemetry::TracedRuntime;
//! use std::time::Duration;
//!
//! // Configure timeline collection
//! let timeline_config = TimelineConfig::builder()
//!     .upload_interval(Duration::from_secs(60))
//!     .format(TimelineFormat::Both)  // Test both formats
//!     .build();
//!
//! // Build the writer and handle
//! let (writer, timeline_handle) = timeline()
//!     .with_config(datadog_opentelemetry::configuration::Config::builder().build())
//!     .with_timeline_config(timeline_config)
//!     .build_writer()
//!     .expect("failed to build timeline writer");
//!
//! // Wrap your Tokio runtime with dial9
//! let (runtime, _guard) = TracedRuntime::build_and_start(
//!     tokio::runtime::Builder::new_multi_thread(),
//!     writer,
//! ).expect("failed to build traced runtime");
//!
//! // ... use the runtime ...
//!
//! // Shutdown gracefully - ORDER IS CRITICAL!
//! // See "Shutdown Sequence" section below.
//! drop(runtime);  // 1. Drop runtime first
//! drop(guard);    // 2. Then drop dial9 guard
//! std::thread::sleep(Duration::from_millis(100));
//! timeline_handle.flush();
//! timeline_handle.shutdown(Duration::from_secs(5)).ok();
//! ```
//!
//! # Shutdown Sequence
//!
//! **CRITICAL**: The shutdown order matters for event delivery!
//!
//! `dial9-tokio-telemetry` uses thread-local buffers (1024 event threshold) in each
//! worker thread. Events only flush from these buffers when:
//! 1. The buffer fills up (1024 events)
//! 2. The worker thread exits (Drop impl on ThreadLocalBuffer)
//! 3. Explicit flush via dial9's API
//!
//! For short-lived applications or demos, the buffers may never fill, so you must
//! ensure worker threads exit before the dial9 guard is dropped. The correct sequence:
//!
//! ```rust,ignore
//! // 1. Drop runtime FIRST - this makes worker threads exit, flushing their
//! //    thread-local buffers to the CentralCollector
//! drop(runtime);
//!
//! // 2. Drop dial9 guard - this triggers final flush from collector to TraceWriter
//! drop(guard);
//!
//! // 3. Brief pause to let events propagate through channels
//! std::thread::sleep(Duration::from_millis(100));
//!
//! // 4. Flush our timeline to upload any remaining events
//! timeline_handle.flush();
//!
//! // 5. Shutdown the timeline worker
//! timeline_handle.shutdown(Duration::from_secs(5)).ok();
//! ```
//!
//! **Wrong order** (guard dropped before runtime):
//! - Worker threads still running, holding unflushed events in thread-local buffers
//! - Guard drop tries to flush, but workers haven't exited yet
//! - Events are lost, tasks appear "unscheduled" with no poll events

mod buffer;
mod config;
mod serializer;
mod uploader;
mod worker;
mod writer;

use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Sender;

use crate::core::configuration::Config;

pub use config::{TimelineConfig, TimelineConfigBuilder, TimelineFormat};
pub use worker::ShutdownError;
pub use writer::DatadogTimelineWriter;

/// Default channel capacity for events.
const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// Handle for controlling the timeline collection.
///
/// Use this handle to trigger flushes or shut down the timeline worker.
pub struct TimelineHandle {
    /// Worker handle for coordination.
    worker_handle: worker::TimelineWorkerHandle,
    /// Channel sender (kept to detect disconnection).
    _sender: Sender<buffer::OwnedEvent>,
}

impl TimelineHandle {
    /// Requests an immediate flush of buffered events.
    pub fn flush(&self) {
        self.worker_handle.flush();
    }

    /// Shuts down the timeline worker gracefully.
    ///
    /// This will flush any remaining buffered events before shutting down.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for shutdown to complete.
    ///
    /// # Returns
    /// `Ok(())` if shutdown completed successfully, or an error if it timed out
    /// or encountered other issues.
    pub fn shutdown(self, timeout: Duration) -> Result<(), ShutdownError> {
        self.worker_handle.shutdown(timeout)
    }
}

/// Builder for creating a timeline writer and handle.
pub struct TimelineBuilder {
    config: Option<Config>,
    timeline_config: Option<TimelineConfig>,
    channel_capacity: usize,
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TimelineBuilder {
    /// Creates a new timeline builder.
    fn new() -> Self {
        Self {
            config: None,
            timeline_config: None,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    /// Sets the Datadog configuration.
    ///
    /// If not set, a default configuration will be used.
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the timeline-specific configuration.
    ///
    /// If not set, default timeline configuration will be used.
    pub fn with_timeline_config(mut self, config: TimelineConfig) -> Self {
        self.timeline_config = Some(config);
        self
    }

    /// Sets the channel capacity for event buffering.
    ///
    /// This controls how many events can be queued before the writer
    /// starts dropping events. Default: 10,000.
    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    /// Builds the timeline writer and handle.
    ///
    /// # Returns
    /// A tuple of `(DatadogTimelineWriter, TimelineHandle)`:
    /// - The writer should be passed to `dial9_tokio_telemetry::TracedRuntime`
    /// - The handle can be used to control flushing and shutdown
    ///
    /// # Errors
    /// Returns an error if the worker thread fails to spawn.
    pub fn build_writer(self) -> Result<(DatadogTimelineWriter, TimelineHandle), BuildError> {
        let config = Arc::new(self.config.unwrap_or_else(|| Config::builder().build()));
        let timeline_config = self.timeline_config.unwrap_or_default();

        // Create bounded channel
        let (sender, receiver) = crossbeam_channel::bounded(self.channel_capacity);

        // Spawn worker thread
        let worker_handle = worker::spawn_worker(Arc::clone(&config), timeline_config, receiver);

        // Create writer
        let writer = DatadogTimelineWriter::new(sender.clone());

        let handle = TimelineHandle {
            worker_handle,
            _sender: sender,
        };

        Ok((writer, handle))
    }
}

/// Error that can occur when building the timeline writer.
#[derive(Debug)]
pub enum BuildError {
    /// Failed to spawn the worker thread.
    SpawnFailed(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::SpawnFailed(msg) => write!(f, "failed to spawn worker: {}", msg),
        }
    }
}

impl std::error::Error for BuildError {}

/// Creates a new timeline builder.
///
/// # Example
///
/// ```rust,ignore
/// use datadog_opentelemetry::tokio_timeline::{timeline, TimelineConfig};
///
/// let (writer, handle) = timeline()
///     .with_config(config)
///     .with_timeline_config(TimelineConfig::default())
///     .build_writer()
///     .expect("failed to build");
/// ```
pub fn timeline() -> TimelineBuilder {
    TimelineBuilder::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_builder_default() {
        let builder = timeline();
        assert!(builder.config.is_none());
        assert!(builder.timeline_config.is_none());
        assert_eq!(builder.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
    }

    #[test]
    fn test_timeline_builder_with_config() {
        let config = Config::builder()
            .set_service("test-service".to_string())
            .build();

        let builder = timeline().with_config(config);
        assert!(builder.config.is_some());
    }

    #[test]
    fn test_timeline_builder_with_timeline_config() {
        let timeline_config = TimelineConfig::builder()
            .upload_interval(Duration::from_secs(30))
            .format(TimelineFormat::Pprof)
            .build();

        let builder = timeline().with_timeline_config(timeline_config);
        assert!(builder.timeline_config.is_some());
    }

    #[test]
    fn test_build_writer() {
        let (writer, handle) = timeline()
            .with_channel_capacity(100)
            .build_writer()
            .expect("failed to build");

        // Writer should exist
        drop(writer);

        // Handle should allow shutdown
        handle.shutdown(Duration::from_secs(5)).ok();
    }

    #[test]
    fn test_handle_flush() {
        let (_writer, handle) = timeline().build_writer().expect("failed to build");

        // Should not panic
        handle.flush();

        handle.shutdown(Duration::from_secs(5)).ok();
    }
}
