// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Configuration for Tokio timeline telemetry.

use std::time::Duration;

/// Default upload interval for timeline data (60 seconds).
const DEFAULT_UPLOAD_INTERVAL: Duration = Duration::from_secs(60);

/// Default maximum buffer size in bytes (10 MB).
const DEFAULT_MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;

/// Default maximum number of buffered events.
const DEFAULT_MAX_BUFFERED_EVENTS: usize = 100_000;

/// Configuration for timeline telemetry collection and upload.
#[derive(Debug, Clone)]
pub struct TimelineConfig {
    /// Interval between uploads to the profiling endpoint.
    pub upload_interval: Duration,
    /// Maximum buffer size in bytes before forcing a flush.
    pub max_buffer_size: usize,
    /// Maximum number of events to buffer before forcing a flush.
    pub max_buffered_events: usize,
}

impl Default for TimelineConfig {
    fn default() -> Self {
        Self {
            upload_interval: DEFAULT_UPLOAD_INTERVAL,
            max_buffer_size: DEFAULT_MAX_BUFFER_SIZE,
            max_buffered_events: DEFAULT_MAX_BUFFERED_EVENTS,
        }
    }
}

impl TimelineConfig {
    /// Creates a new builder for `TimelineConfig`.
    pub fn builder() -> TimelineConfigBuilder {
        TimelineConfigBuilder::default()
    }
}

/// Builder for constructing a `TimelineConfig`.
#[derive(Debug, Clone, Default)]
pub struct TimelineConfigBuilder {
    upload_interval: Option<Duration>,
    max_buffer_size: Option<usize>,
    max_buffered_events: Option<usize>,
}

impl TimelineConfigBuilder {
    /// Sets the upload interval for timeline data.
    ///
    /// Default: 60 seconds.
    pub fn upload_interval(mut self, interval: Duration) -> Self {
        self.upload_interval = Some(interval);
        self
    }

    /// Sets the maximum buffer size in bytes.
    ///
    /// When this limit is reached, a flush is triggered.
    /// Default: 10 MB.
    pub fn max_buffer_size(mut self, size: usize) -> Self {
        self.max_buffer_size = Some(size);
        self
    }

    /// Sets the maximum number of events to buffer.
    ///
    /// When this limit is reached, a flush is triggered.
    /// Default: 100,000 events.
    pub fn max_buffered_events(mut self, count: usize) -> Self {
        self.max_buffered_events = Some(count);
        self
    }

    /// Builds the `TimelineConfig`.
    pub fn build(self) -> TimelineConfig {
        TimelineConfig {
            upload_interval: self.upload_interval.unwrap_or(DEFAULT_UPLOAD_INTERVAL),
            max_buffer_size: self.max_buffer_size.unwrap_or(DEFAULT_MAX_BUFFER_SIZE),
            max_buffered_events: self
                .max_buffered_events
                .unwrap_or(DEFAULT_MAX_BUFFERED_EVENTS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TimelineConfig::default();
        assert_eq!(config.upload_interval, Duration::from_secs(60));
        assert_eq!(config.max_buffer_size, 10 * 1024 * 1024);
        assert_eq!(config.max_buffered_events, 100_000);
    }

    #[test]
    fn test_builder() {
        let config = TimelineConfig::builder()
            .upload_interval(Duration::from_secs(30))
            .max_buffer_size(5 * 1024 * 1024)
            .max_buffered_events(50_000)
            .build();

        assert_eq!(config.upload_interval, Duration::from_secs(30));
        assert_eq!(config.max_buffer_size, 5 * 1024 * 1024);
        assert_eq!(config.max_buffered_events, 50_000);
    }

    #[test]
    fn test_builder_partial() {
        let config = TimelineConfig::builder()
            .upload_interval(Duration::from_secs(120))
            .build();

        assert_eq!(config.upload_interval, Duration::from_secs(120));
        assert_eq!(config.max_buffer_size, DEFAULT_MAX_BUFFER_SIZE);
        assert_eq!(config.max_buffered_events, DEFAULT_MAX_BUFFERED_EVENTS);
    }
}
