// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Serialization formats for timeline data.

pub mod go_trace;
pub mod pprof_timeline;

#[cfg(test)]
mod go_trace_tests;

use std::time::SystemTime;

use crate::tokio_timeline::buffer::OwnedEvent;

/// Result of serializing timeline data.
#[derive(Debug)]
pub struct SerializedTimeline {
    /// The serialized data.
    pub data: Vec<u8>,
    /// Profile type name for multipart form field (e.g., "execution-trace").
    #[allow(dead_code)]
    pub name: &'static str,
    /// Filename for the attachment (e.g., "go.trace" or "timeline.pprof").
    pub filename: &'static str,
    /// MIME type for the attachment.
    pub content_type: &'static str,
}

/// Error type for serialization failures.
#[derive(Debug)]
pub enum SerializeError {
    /// Failed to encode data.
    EncodingError(String),
    /// Failed to compress data.
    CompressionError(String),
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializeError::EncodingError(msg) => write!(f, "encoding error: {}", msg),
            SerializeError::CompressionError(msg) => write!(f, "compression error: {}", msg),
        }
    }
}

impl std::error::Error for SerializeError {}

/// Trait for serializing timeline events into a specific format.
pub trait TimelineSerializer: Send {
    /// Serializes a batch of events into the target format.
    ///
    /// # Arguments
    /// * `events` - The events to serialize.
    /// * `batch_start` - When this batch of events started.
    /// * `batch_end` - When this batch of events ended.
    ///
    /// # Returns
    /// The serialized timeline data, or an error if serialization fails.
    fn serialize(
        &mut self,
        events: &[OwnedEvent],
        batch_start: SystemTime,
        batch_end: SystemTime,
    ) -> Result<SerializedTimeline, SerializeError>;
}
