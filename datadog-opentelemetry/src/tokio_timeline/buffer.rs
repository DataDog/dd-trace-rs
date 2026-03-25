// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Event buffering for Tokio timeline telemetry.

use std::time::SystemTime;

/// Owned representation of a dial9 telemetry event.
///
/// These events are converted from `dial9_tokio_telemetry::RawEvent` to allow
/// buffering across thread boundaries without lifetime constraints.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum OwnedEvent {
    /// A task started being polled on a worker thread.
    PollStart {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Worker thread ID.
        worker_id: u8,
        /// Task ID being polled.
        task_id: u64,
        /// Source location where the task was spawned.
        location: String,
    },
    /// A task finished being polled (yielded or completed a poll cycle).
    PollEnd {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Worker thread ID.
        worker_id: u8,
    },
    /// A worker thread parked (no work available).
    WorkerPark {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Worker thread ID.
        worker_id: u8,
        /// CPU time consumed before parking in nanoseconds.
        cpu_time_nanos: u64,
    },
    /// A worker thread unparked (work became available).
    WorkerUnpark {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Worker thread ID.
        worker_id: u8,
        /// Time spent waiting for the scheduler in nanoseconds.
        sched_wait_nanos: u64,
    },
    /// A new task was spawned.
    TaskSpawn {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Task ID of the spawned task.
        task_id: u64,
        /// Source location where the task was spawned.
        location: String,
    },
    /// A task terminated (completed execution).
    TaskTerminate {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Task ID of the terminated task.
        task_id: u64,
    },
    /// A waker was invoked to wake a task.
    WakeEvent {
        /// Timestamp in nanoseconds since an arbitrary epoch.
        timestamp_nanos: u64,
        /// Task ID that invoked the waker.
        waker_task_id: u64,
        /// Task ID that was woken.
        woken_task_id: u64,
    },
}

impl OwnedEvent {
    /// Returns the timestamp of this event in nanoseconds.
    pub fn timestamp_nanos(&self) -> u64 {
        match self {
            OwnedEvent::PollStart {
                timestamp_nanos, ..
            }
            | OwnedEvent::PollEnd {
                timestamp_nanos, ..
            }
            | OwnedEvent::WorkerPark {
                timestamp_nanos, ..
            }
            | OwnedEvent::WorkerUnpark {
                timestamp_nanos, ..
            }
            | OwnedEvent::TaskSpawn {
                timestamp_nanos, ..
            }
            | OwnedEvent::TaskTerminate {
                timestamp_nanos, ..
            }
            | OwnedEvent::WakeEvent {
                timestamp_nanos, ..
            } => *timestamp_nanos,
        }
    }

    /// Returns an estimated size in bytes for this event (for buffer size tracking).
    pub fn estimated_size(&self) -> usize {
        // Base size for enum discriminant + fixed fields
        let base_size = std::mem::size_of::<Self>();

        // Add string allocation sizes
        match self {
            OwnedEvent::PollStart { location, .. } | OwnedEvent::TaskSpawn { location, .. } => {
                base_size + location.len()
            }
            _ => base_size,
        }
    }
}

/// Buffer for collecting timeline events before serialization and upload.
#[derive(Debug)]
pub struct EventBuffer {
    /// Buffered events.
    events: Vec<OwnedEvent>,
    /// Start time of the current batch.
    batch_start: SystemTime,
    /// Total estimated size of buffered events in bytes.
    current_size: usize,
    /// Maximum buffer size in bytes.
    max_size: usize,
    /// Maximum number of events to buffer.
    max_events: usize,
}

#[allow(dead_code)]
impl EventBuffer {
    /// Creates a new event buffer with the given limits.
    pub fn new(max_size: usize, max_events: usize) -> Self {
        Self {
            events: Vec::with_capacity(max_events.min(10_000)),
            batch_start: SystemTime::now(),
            current_size: 0,
            max_size,
            max_events,
        }
    }

    /// Adds an event to the buffer.
    ///
    /// Returns `true` if the buffer should be flushed (limits exceeded).
    pub fn push(&mut self, event: OwnedEvent) -> bool {
        self.current_size += event.estimated_size();
        self.events.push(event);

        self.should_flush()
    }

    /// Returns `true` if the buffer should be flushed.
    pub fn should_flush(&self) -> bool {
        self.events.len() >= self.max_events || self.current_size >= self.max_size
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Returns the number of events in the buffer.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns the current estimated size of the buffer in bytes.
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Returns the batch start time.
    pub fn batch_start(&self) -> SystemTime {
        self.batch_start
    }

    /// Drains all events from the buffer and resets it.
    ///
    /// Returns the drained events and the batch start time.
    pub fn drain(&mut self) -> (Vec<OwnedEvent>, SystemTime) {
        let events = std::mem::replace(
            &mut self.events,
            Vec::with_capacity(self.max_events.min(10_000)),
        );
        let batch_start = self.batch_start;
        self.batch_start = SystemTime::now();
        self.current_size = 0;
        (events, batch_start)
    }

    /// Returns a reference to the buffered events.
    pub fn events(&self) -> &[OwnedEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owned_event_timestamp() {
        let event = OwnedEvent::PollStart {
            timestamp_nanos: 12345,
            worker_id: 0,
            task_id: 1,
            location: "test.rs:10".to_string(),
        };
        assert_eq!(event.timestamp_nanos(), 12345);
    }

    #[test]
    fn test_owned_event_estimated_size() {
        let event = OwnedEvent::PollStart {
            timestamp_nanos: 12345,
            worker_id: 0,
            task_id: 1,
            location: "test.rs:10".to_string(),
        };
        // Should include base size + string length
        assert!(event.estimated_size() > 10);

        let event = OwnedEvent::PollEnd {
            timestamp_nanos: 12345,
            worker_id: 0,
        };
        // No string, just base size
        assert!(event.estimated_size() > 0);
    }

    #[test]
    fn test_buffer_push() {
        let mut buffer = EventBuffer::new(1024 * 1024, 100);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);

        let event = OwnedEvent::PollEnd {
            timestamp_nanos: 12345,
            worker_id: 0,
        };
        let should_flush = buffer.push(event);
        assert!(!should_flush);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn test_buffer_max_events() {
        let mut buffer = EventBuffer::new(1024 * 1024, 2);

        buffer.push(OwnedEvent::PollEnd {
            timestamp_nanos: 1,
            worker_id: 0,
        });
        assert!(!buffer.should_flush());

        let should_flush = buffer.push(OwnedEvent::PollEnd {
            timestamp_nanos: 2,
            worker_id: 0,
        });
        assert!(should_flush);
    }

    #[test]
    fn test_buffer_drain() {
        let mut buffer = EventBuffer::new(1024 * 1024, 100);
        buffer.push(OwnedEvent::PollEnd {
            timestamp_nanos: 1,
            worker_id: 0,
        });
        buffer.push(OwnedEvent::PollEnd {
            timestamp_nanos: 2,
            worker_id: 0,
        });

        let (events, _start) = buffer.drain();
        assert_eq!(events.len(), 2);
        assert!(buffer.is_empty());
        assert_eq!(buffer.size(), 0);
    }
}
