// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! TraceWriter implementation for dial9-tokio-telemetry integration.

use std::hash::{Hash, Hasher};
use std::io;

use crossbeam_channel::Sender;
use dial9_tokio_telemetry::telemetry::events::RawEvent;
use dial9_tokio_telemetry::telemetry::TraceWriter;

use crate::tokio_timeline::buffer::OwnedEvent;

/// A TraceWriter that converts dial9 events and sends them to the timeline worker.
///
/// This writer implements the `dial9_tokio_telemetry::telemetry::TraceWriter` trait,
/// allowing it to receive runtime telemetry events from a `TracedRuntime`.
pub struct DatadogTimelineWriter {
    /// Channel sender for events.
    sender: Sender<OwnedEvent>,
}

/// Converts a TaskId to u64 by hashing it.
fn task_id_to_u64<T: Hash>(task_id: &T) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    task_id.hash(&mut hasher);
    hasher.finish()
}

impl DatadogTimelineWriter {
    /// Creates a new timeline writer with the given channel sender.
    pub(crate) fn new(sender: Sender<OwnedEvent>) -> Self {
        Self { sender }
    }

    /// Converts a RawEvent to an OwnedEvent.
    fn convert_event(event: &RawEvent) -> Option<OwnedEvent> {
        match event {
            RawEvent::PollStart {
                timestamp_nanos,
                worker_id,
                task_id,
                location,
                ..
            } => Some(OwnedEvent::PollStart {
                timestamp_nanos: *timestamp_nanos,
                worker_id: worker_id.as_u64() as u8,
                task_id: task_id_to_u64(task_id),
                location: format!("{}:{}", location.file(), location.line()),
            }),
            RawEvent::PollEnd {
                timestamp_nanos,
                worker_id,
                ..
            } => Some(OwnedEvent::PollEnd {
                timestamp_nanos: *timestamp_nanos,
                worker_id: worker_id.as_u64() as u8,
            }),
            RawEvent::WorkerPark {
                timestamp_nanos,
                worker_id,
                cpu_time_nanos,
                ..
            } => Some(OwnedEvent::WorkerPark {
                timestamp_nanos: *timestamp_nanos,
                worker_id: worker_id.as_u64() as u8,
                cpu_time_nanos: *cpu_time_nanos,
            }),
            RawEvent::WorkerUnpark {
                timestamp_nanos,
                worker_id,
                sched_wait_delta_nanos,
                ..
            } => Some(OwnedEvent::WorkerUnpark {
                timestamp_nanos: *timestamp_nanos,
                worker_id: worker_id.as_u64() as u8,
                sched_wait_nanos: *sched_wait_delta_nanos,
            }),
            RawEvent::TaskSpawn {
                timestamp_nanos,
                task_id,
                location,
                ..
            } => Some(OwnedEvent::TaskSpawn {
                timestamp_nanos: *timestamp_nanos,
                task_id: task_id_to_u64(task_id),
                location: format!("{}:{}", location.file(), location.line()),
            }),
            RawEvent::TaskTerminate {
                timestamp_nanos,
                task_id,
                ..
            } => Some(OwnedEvent::TaskTerminate {
                timestamp_nanos: *timestamp_nanos,
                task_id: task_id_to_u64(task_id),
            }),
            RawEvent::WakeEvent {
                timestamp_nanos,
                waker_task_id,
                woken_task_id,
                ..
            } => Some(OwnedEvent::WakeEvent {
                timestamp_nanos: *timestamp_nanos,
                waker_task_id: task_id_to_u64(waker_task_id),
                woken_task_id: task_id_to_u64(woken_task_id),
            }),
            // Ignore other event types (QueueSample, CpuSample)
            _ => None,
        }
    }

    /// Sends an event to the worker, dropping if the channel is full.
    fn send_event(&self, event: OwnedEvent) {
        // Use try_send to avoid blocking on the hot path
        // If the channel is full, we drop the event rather than blocking
        let _ = self.sender.try_send(event);
    }
}

impl TraceWriter for DatadogTimelineWriter {
    fn write_event(&mut self, event: &RawEvent) -> io::Result<()> {
        if let Some(owned) = Self::convert_event(event) {
            self.send_event(owned);
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffering in the writer, events are sent immediately
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writer_creation() {
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let _writer = DatadogTimelineWriter::new(sender);
    }

    #[test]
    fn test_flush() {
        let (sender, _receiver) = crossbeam_channel::unbounded();
        let mut writer = DatadogTimelineWriter::new(sender);
        // Should not panic or error
        writer.flush().unwrap();
    }
}
