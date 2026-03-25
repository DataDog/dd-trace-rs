// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Go v2 execution trace format serializer.
//!
//! This module produces binary data compatible with Go's runtime/trace format (version 2),
//! which can be visualized in Go's trace viewer or compatible tools.

use std::collections::HashMap;
use std::time::SystemTime;

use super::{SerializeError, SerializedTimeline, TimelineSerializer};
use crate::tokio_timeline::buffer::OwnedEvent;

/// Go trace header for version 1.23 format.
const GO_TRACE_HEADER: &[u8; 16] = b"go 1.23 trace\x00\x00\x00";

/// Go trace event types (v2 format for Go 1.22+).
/// From go/src/internal/trace/v2/event/go122/event.go
mod event_type {
    /// Event batch header.
    pub const EV_EVENT_BATCH: u8 = 1;
    /// Stack table batch.
    pub const EV_STACKS: u8 = 2;
    /// String table batch.
    pub const EV_STRINGS: u8 = 4;
    /// Frequency event - provides timestamp calibration.
    pub const EV_FREQUENCY: u8 = 8;
    /// Number of Ps changed.
    pub const EV_PROCS_CHANGE: u8 = 10;
    /// Processor (P) started.
    pub const EV_PROC_START: u8 = 11;
    /// Processor (P) stopped.
    pub const EV_PROC_STOP: u8 = 12;
    /// Initial P status (for establishing state).
    pub const EV_PROC_STATUS: u8 = 14;
    /// Goroutine created.
    pub const EV_GO_CREATE: u8 = 15;
    /// Goroutine started running.
    pub const EV_GO_START: u8 = 17;
    /// Goroutine destroyed.
    pub const EV_GO_DESTROY: u8 = 18;
    /// Goroutine stopped (yielded/preempted).
    pub const EV_GO_STOP: u8 = 19;
    /// Goroutine unblocked.
    pub const EV_GO_UNBLOCK: u8 = 21;
    /// Initial goroutine status (for establishing state).
    pub const EV_GO_STATUS: u8 = 25;
}

/// Serializer for Go v2 execution trace format.
#[derive(Debug, Default)]
pub struct GoTraceSerializer {
    /// String table for deduplication.
    string_table: HashMap<String, u64>,
    /// Next string ID.
    next_string_id: u64,
}

impl GoTraceSerializer {
    /// Creates a new Go trace serializer.
    pub fn new() -> Self {
        Self {
            string_table: HashMap::new(),
            next_string_id: 1, // 0 is reserved for empty string
        }
    }

    /// Gets or creates a string ID for the given string.
    fn get_or_create_string_id(&mut self, s: &str) -> u64 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&id) = self.string_table.get(s) {
            return id;
        }
        let id = self.next_string_id;
        self.next_string_id += 1;
        self.string_table.insert(s.to_string(), id);
        id
    }

    /// Writes the string table batch to the output.
    fn write_string_table(&self, output: &mut Vec<u8>) {
        if self.string_table.is_empty() {
            return;
        }

        // Collect strings sorted by ID
        let mut strings: Vec<(&String, &u64)> = self.string_table.iter().collect();
        strings.sort_by_key(|(_, id)| *id);

        // Build string batch data
        let mut batch_data = Vec::new();
        for (s, id) in strings {
            write_varint(&mut batch_data, *id);
            write_varint(&mut batch_data, s.len() as u64);
            batch_data.extend_from_slice(s.as_bytes());
        }

        // Write string batch header: type, gen, size, data
        output.push(event_type::EV_STRINGS);
        write_varint(output, 1); // generation = 1
        write_varint(output, batch_data.len() as u64);
        output.extend_from_slice(&batch_data);
    }

    /// Writes an event batch for a worker.
    fn write_event_batch(
        &mut self,
        output: &mut Vec<u8>,
        worker_id: u8,
        events: &[OwnedEvent],
        absolute_base_timestamp: u64,
        min_event_timestamp: u64,
    ) {
        if events.is_empty() {
            return;
        }

        let mut batch_data = Vec::new();
        let mut last_timestamp = min_event_timestamp;

        for event in events {
            let timestamp = event.timestamp_nanos();
            let delta = timestamp.saturating_sub(last_timestamp);
            last_timestamp = timestamp;

            match event {
                OwnedEvent::TaskSpawn {
                    task_id, location, ..
                } => {
                    // EvGoCreate: dt, new_g, new_stack, stack
                    batch_data.push(event_type::EV_GO_CREATE);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, *task_id); // new goroutine ID
                    write_varint(&mut batch_data, 0); // new_stack (no stack info)
                    write_varint(&mut batch_data, 0); // creator stack (no stack info)
                    // Store location in string table for potential future use
                    let _ = self.get_or_create_string_id(location);
                }
                OwnedEvent::PollStart { task_id, .. } => {
                    // EvGoStart: dt, g, g_seq
                    batch_data.push(event_type::EV_GO_START);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, *task_id); // goroutine ID
                    write_varint(&mut batch_data, 0); // sequence number
                }
                OwnedEvent::PollEnd { .. } => {
                    // EvGoStop: dt, reason_string, stack
                    batch_data.push(event_type::EV_GO_STOP);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, 0); // reason string ID (empty)
                    write_varint(&mut batch_data, 0); // stack ID (no stack info)
                }
                OwnedEvent::TaskTerminate { .. } => {
                    // EvGoDestroy: dt (just timestamp delta)
                    batch_data.push(event_type::EV_GO_DESTROY);
                    write_varint(&mut batch_data, delta);
                }
                OwnedEvent::WorkerPark { .. } => {
                    // EvProcStop: dt (just timestamp delta)
                    batch_data.push(event_type::EV_PROC_STOP);
                    write_varint(&mut batch_data, delta);
                }
                OwnedEvent::WorkerUnpark { .. } => {
                    // EvProcStart: dt, p, p_seq
                    batch_data.push(event_type::EV_PROC_START);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, worker_id as u64); // P ID
                    write_varint(&mut batch_data, 0); // P sequence
                }
                OwnedEvent::WakeEvent {
                    woken_task_id,
                    ..
                } => {
                    // EvGoUnblock: dt, g, g_seq, stack
                    batch_data.push(event_type::EV_GO_UNBLOCK);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, *woken_task_id); // goroutine being unblocked
                    write_varint(&mut batch_data, 0); // sequence number
                    write_varint(&mut batch_data, 0); // stack ID (no stack info)
                }
            }
        }

        // Write event batch header: type, gen, M, timestamp, byte count, data
        // Go trace v2 format: EventBatch has generation after type
        output.push(event_type::EV_EVENT_BATCH);
        write_varint(output, 1); // generation = 1
        write_varint(output, worker_id as u64); // M ID
        write_varint(output, absolute_base_timestamp); // base timestamp
        write_varint(output, batch_data.len() as u64); // byte count
        output.extend_from_slice(&batch_data);
    }

    /// Groups events by worker ID.
    fn group_by_worker(events: &[OwnedEvent]) -> HashMap<u8, Vec<&OwnedEvent>> {
        let mut groups: HashMap<u8, Vec<&OwnedEvent>> = HashMap::new();

        for event in events {
            let worker_id = match event {
                OwnedEvent::PollStart { worker_id, .. }
                | OwnedEvent::PollEnd { worker_id, .. }
                | OwnedEvent::WorkerPark { worker_id, .. }
                | OwnedEvent::WorkerUnpark { worker_id, .. } => *worker_id,
                // Events without worker ID go to worker 0
                OwnedEvent::TaskSpawn { .. }
                | OwnedEvent::TaskTerminate { .. }
                | OwnedEvent::WakeEvent { .. } => 0,
            };

            groups.entry(worker_id).or_default().push(event);
        }

        groups
    }
}

impl TimelineSerializer for GoTraceSerializer {
    fn serialize(
        &mut self,
        events: &[OwnedEvent],
        batch_start: SystemTime,
        _batch_end: SystemTime,
    ) -> Result<SerializedTimeline, SerializeError> {
        // Reset string table for each batch
        self.string_table.clear();
        self.next_string_id = 1;

        let mut output = Vec::new();

        // Write header
        output.extend_from_slice(GO_TRACE_HEADER);

        // Go trace uses monotonic timestamps (relative to trace start), not Unix time.
        // We use the minimum event timestamp as the base (start of trace).
        let min_event_timestamp = events
            .iter()
            .map(|e| e.timestamp_nanos())
            .min()
            .unwrap_or(0);

        // Base timestamp for the first batch - use a reasonable starting value
        // The events have relative timestamps, so we use them directly
        let base_timestamp = min_event_timestamp;

        // First pass: collect all strings and build events grouped by worker
        let grouped = Self::group_by_worker(events);

        // Pre-populate string table by scanning all events
        for event in events {
            if let OwnedEvent::TaskSpawn { location, .. } | OwnedEvent::PollStart { location, .. } =
                event
            {
                self.get_or_create_string_id(location);
            }
        }

        // Go trace v2 format: First EventBatch contains Frequency and initial state

        // Collect unique worker IDs for initial status
        let worker_ids: Vec<u8> = grouped.keys().copied().collect();
        let num_workers = worker_ids.len().max(1) as u64;

        // Build initial batch data with Frequency and setup events
        let mut init_data = Vec::new();

        // Frequency event
        init_data.push(event_type::EV_FREQUENCY);
        write_varint(&mut init_data, 1_000_000_000); // 1GHz = timestamps in nanoseconds

        // ProcsChange: dt, procs - establish number of processors
        init_data.push(event_type::EV_PROCS_CHANGE);
        write_varint(&mut init_data, 0); // dt = 0
        write_varint(&mut init_data, num_workers); // number of Ps

        // ProcStatus for each P: dt, p, status (status: 0=idle, 1=running)
        for &worker_id in &worker_ids {
            init_data.push(event_type::EV_PROC_STATUS);
            write_varint(&mut init_data, 0); // dt = 0
            write_varint(&mut init_data, worker_id as u64); // P ID
            write_varint(&mut init_data, 1); // status = running
        }

        // Write first EventBatch with initialization
        output.push(event_type::EV_EVENT_BATCH);
        write_varint(&mut output, 1); // generation = 1
        write_varint(&mut output, u64::MAX); // M = -1 (no thread, special)
        write_varint(&mut output, base_timestamp); // base timestamp
        write_varint(&mut output, init_data.len() as u64);
        output.extend_from_slice(&init_data);

        // Write string table
        self.write_string_table(&mut output);

        // Write event batches for each worker
        for (worker_id, worker_events) in grouped {
            let owned_events: Vec<OwnedEvent> = worker_events.into_iter().cloned().collect();
            self.write_event_batch(
                &mut output,
                worker_id,
                &owned_events,
                base_timestamp,
                min_event_timestamp,
            );
        }

        Ok(SerializedTimeline {
            data: output,
            filename: "go.trace",
            content_type: "application/octet-stream",
        })
    }
}

/// Writes a variable-length integer (LEB128 unsigned) to the output.
fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Reads a variable-length integer (LEB128 unsigned) from input.
#[cfg(test)]
fn read_varint(input: &[u8], pos: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= input.len() {
            break;
        }
        let byte = input[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_varint_small() {
        let mut output = Vec::new();
        write_varint(&mut output, 0);
        assert_eq!(output, vec![0]);

        output.clear();
        write_varint(&mut output, 1);
        assert_eq!(output, vec![1]);

        output.clear();
        write_varint(&mut output, 127);
        assert_eq!(output, vec![127]);
    }

    #[test]
    fn test_write_varint_medium() {
        let mut output = Vec::new();
        write_varint(&mut output, 128);
        assert_eq!(output, vec![0x80, 0x01]);

        output.clear();
        write_varint(&mut output, 300);
        assert_eq!(output, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_write_varint_large() {
        let mut output = Vec::new();
        write_varint(&mut output, 1_000_000_000);
        let mut pos = 0;
        let read_back = read_varint(&output, &mut pos);
        assert_eq!(read_back, 1_000_000_000);
    }

    #[test]
    fn test_read_varint_roundtrip() {
        let test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, u64::MAX];
        for &value in &test_values {
            let mut output = Vec::new();
            write_varint(&mut output, value);
            let mut pos = 0;
            let read_back = read_varint(&output, &mut pos);
            assert_eq!(read_back, value, "roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_serializer_header() {
        let mut serializer = GoTraceSerializer::new();
        let events = vec![];
        let result = serializer
            .serialize(&events, SystemTime::now(), SystemTime::now())
            .unwrap();

        assert!(result.data.starts_with(GO_TRACE_HEADER));
        assert_eq!(result.filename, "go.trace");
        assert_eq!(result.content_type, "application/octet-stream");
    }

    #[test]
    fn test_serializer_with_events() {
        let mut serializer = GoTraceSerializer::new();
        let events = vec![
            OwnedEvent::TaskSpawn {
                timestamp_nanos: 1000,
                task_id: 1,
                location: "main.rs:10".to_string(),
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 2000,
                worker_id: 0,
                task_id: 1,
                location: "main.rs:10".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 3000,
                worker_id: 0,
            },
            OwnedEvent::TaskTerminate {
                timestamp_nanos: 4000,
                task_id: 1,
            },
        ];

        let result = serializer
            .serialize(&events, SystemTime::now(), SystemTime::now())
            .unwrap();

        // Should have header and some data
        assert!(result.data.len() > GO_TRACE_HEADER.len());
        assert!(result.data.starts_with(GO_TRACE_HEADER));
    }

    #[test]
    fn test_string_table_deduplication() {
        let mut serializer = GoTraceSerializer::new();

        // Same string should get same ID
        let id1 = serializer.get_or_create_string_id("test");
        let id2 = serializer.get_or_create_string_id("test");
        assert_eq!(id1, id2);

        // Different string should get different ID
        let id3 = serializer.get_or_create_string_id("other");
        assert_ne!(id1, id3);

        // Empty string always returns 0
        let id_empty = serializer.get_or_create_string_id("");
        assert_eq!(id_empty, 0);
    }

    #[test]
    fn test_group_by_worker() {
        let events = vec![
            OwnedEvent::PollStart {
                timestamp_nanos: 1000,
                worker_id: 0,
                task_id: 1,
                location: String::new(),
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 2000,
                worker_id: 1,
                task_id: 2,
                location: String::new(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 3000,
                worker_id: 0,
            },
        ];

        let groups = GoTraceSerializer::group_by_worker(&events);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.get(&0).map(|v| v.len()), Some(2));
        assert_eq!(groups.get(&1).map(|v| v.len()), Some(1));
    }
}
