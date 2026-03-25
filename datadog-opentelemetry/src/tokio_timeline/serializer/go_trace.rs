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
/// From go/src/internal/trace/event/go122/event.go
mod event_type {
    // Structural events (iota starts at 0, EvNone=0 is unused)
    /// Event batch header [gen, m, time, size].
    pub const EV_EVENT_BATCH: u8 = 1;
    /// Stack table batch.
    pub const EV_STACKS: u8 = 2;
    // EvStack = 3
    /// String table batch.
    pub const EV_STRINGS: u8 = 4;
    // EvString = 5
    // EvCPUSamples = 6
    // EvCPUSample = 7
    /// Frequency event - provides timestamp units per sec [freq].
    pub const EV_FREQUENCY: u8 = 8;

    // Procs (starting at 9)
    /// GOMAXPROCS change [timestamp, GOMAXPROCS, stack ID].
    pub const EV_PROCS_CHANGE: u8 = 9;
    /// P started [timestamp, P ID, P seq].
    pub const EV_PROC_START: u8 = 10;
    /// P stopped [timestamp].
    pub const EV_PROC_STOP: u8 = 11;
    // EvProcSteal = 12
    /// P status at generation start [timestamp, P ID, status].
    pub const EV_PROC_STATUS: u8 = 13;

    // Goroutines (starting at 14)
    /// Goroutine creation [timestamp, new goroutine ID, new stack ID, stack ID].
    pub const EV_GO_CREATE: u8 = 14;
    // EvGoCreateSyscall = 15
    /// Goroutine starts running [timestamp, goroutine ID, goroutine seq].
    pub const EV_GO_START: u8 = 16;
    /// Goroutine ends [timestamp].
    pub const EV_GO_DESTROY: u8 = 17;
    // EvGoDestroySyscall = 18
    /// Goroutine yields its time, but is runnable [timestamp, reason, stack ID].
    pub const EV_GO_STOP: u8 = 19;
    // EvGoBlock = 20
    /// Goroutine is unblocked [timestamp, goroutine ID, goroutine seq, stack ID].
    pub const EV_GO_UNBLOCK: u8 = 21;
    // EvGoSyscallBegin = 22
    // EvGoSyscallEnd = 23
    // EvGoSyscallEndBlocked = 24
    /// Goroutine status at generation start [timestamp, goroutine ID, thread ID, status].
    pub const EV_GO_STATUS: u8 = 25;
}

/// Serializer for Go v2 execution trace format.
#[derive(Debug, Default)]
pub struct GoTraceSerializer {
    /// String table for deduplication.
    string_table: HashMap<String, u64>,
    /// Next string ID.
    next_string_id: u64,
    /// Task ID mapping (dial9 task ID -> small sequential goroutine ID).
    task_id_map: HashMap<u64, u64>,
    /// Next goroutine ID to assign.
    next_goroutine_id: u64,
}

impl GoTraceSerializer {
    /// Creates a new Go trace serializer.
    pub fn new() -> Self {
        Self {
            string_table: HashMap::new(),
            next_string_id: 1, // 0 is reserved for empty string
            task_id_map: HashMap::new(),
            next_goroutine_id: 1, // Goroutine IDs start at 1 (0 is invalid in Go)
        }
    }

    /// Maps a dial9 task ID to a small sequential goroutine ID.
    fn map_task_id(&mut self, task_id: u64) -> u64 {
        if let Some(&g_id) = self.task_id_map.get(&task_id) {
            return g_id;
        }
        let g_id = self.next_goroutine_id;
        self.next_goroutine_id += 1;
        self.task_id_map.insert(task_id, g_id);
        g_id
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
                    // Skip - GoCreate events are emitted upfront for all goroutines
                    // Just ensure the task is mapped and location is in string table
                    let _ = self.map_task_id(*task_id);
                    let _ = self.get_or_create_string_id(location);
                }
                OwnedEvent::PollStart { task_id, .. } => {
                    // EvGoStart: dt, g, g_seq
                    let g_id = self.map_task_id(*task_id);
                    batch_data.push(event_type::EV_GO_START);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, g_id); // goroutine ID (mapped)
                    write_varint(&mut batch_data, 0); // sequence number
                }
                OwnedEvent::PollEnd { .. } => {
                    // EvGoStop: dt, reason_string, stack
                    batch_data.push(event_type::EV_GO_STOP);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, 0); // reason string ID (empty)
                    write_varint(&mut batch_data, 0); // stack ID (no stack info)
                }
                OwnedEvent::TaskTerminate { task_id, .. } => {
                    // EvGoDestroy: dt (just timestamp delta)
                    // Note: We don't need to map the ID here, just emit the event
                    let _ = self.map_task_id(*task_id); // ensure it's mapped for consistency
                    batch_data.push(event_type::EV_GO_DESTROY);
                    write_varint(&mut batch_data, delta);
                }
                OwnedEvent::WorkerPark { .. } | OwnedEvent::WorkerUnpark { .. } => {
                    // Skip P start/stop events when all events are on a single M
                    // These would require multi-M support to work correctly
                }
                OwnedEvent::WakeEvent {
                    woken_task_id,
                    ..
                } => {
                    // EvGoUnblock: dt, g, g_seq, stack
                    let g_id = self.map_task_id(*woken_task_id);
                    batch_data.push(event_type::EV_GO_UNBLOCK);
                    write_varint(&mut batch_data, delta);
                    write_varint(&mut batch_data, g_id); // goroutine being unblocked (mapped)
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

    /// Groups events by worker ID, sorted by timestamp within each group.
    fn group_by_worker(events: &[OwnedEvent]) -> HashMap<u8, Vec<&OwnedEvent>> {
        let mut groups: HashMap<u8, Vec<&OwnedEvent>> = HashMap::new();

        // First, collect events into groups
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

        // Sort each group by timestamp
        for (_worker_id, group) in groups.iter_mut() {
            group.sort_by_key(|e| e.timestamp_nanos());
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
        // Reset state for each batch
        self.string_table.clear();
        self.next_string_id = 1;
        self.task_id_map.clear();
        self.next_goroutine_id = 1;

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

        // First pass: collect all task IDs and map them to small sequential IDs
        // Also collect strings
        for event in events {
            match event {
                OwnedEvent::TaskSpawn {
                    task_id, location, ..
                } => {
                    self.map_task_id(*task_id);
                    self.get_or_create_string_id(location);
                }
                OwnedEvent::PollStart {
                    task_id, location, ..
                } => {
                    self.map_task_id(*task_id);
                    self.get_or_create_string_id(location);
                }
                OwnedEvent::TaskTerminate { task_id, .. } => {
                    self.map_task_id(*task_id);
                }
                OwnedEvent::WakeEvent {
                    waker_task_id,
                    woken_task_id,
                    ..
                } => {
                    self.map_task_id(*waker_task_id);
                    self.map_task_id(*woken_task_id);
                }
                _ => {}
            }
        }

        // Group events by worker for later processing
        let grouped = Self::group_by_worker(events);

        // Go trace v2 format structure (based on real Go traces):
        // 1. First EventBatch (M=-1): ONLY Frequency event
        // 2. Second EventBatch: ProcsChange
        // 3. Third EventBatch: ProcStatus for each P
        // 4. Fourth EventBatch: GoStatus for each goroutine (to establish initial state)
        // 5. Event batches per worker with actual events

        // Collect unique worker IDs for initial status
        let mut worker_ids: Vec<u8> = grouped.keys().copied().collect();
        worker_ids.sort();
        let num_workers = worker_ids.len().max(1) as u64;

        // === First batch: Frequency only (M=-1) ===
        let mut freq_data = Vec::new();
        freq_data.push(event_type::EV_FREQUENCY);
        write_varint(&mut freq_data, 1_000_000_000); // 1GHz = timestamps in nanoseconds

        output.push(event_type::EV_EVENT_BATCH);
        write_varint(&mut output, 1); // generation = 1
        write_varint(&mut output, u64::MAX); // M = -1 (special)
        write_varint(&mut output, base_timestamp); // base timestamp
        write_varint(&mut output, freq_data.len() as u64);
        output.extend_from_slice(&freq_data);

        // === Second batch: ProcsChange (M=0) ===
        // This sets GOMAXPROCS - must be on a real M, not M=-1
        let mut procs_data = Vec::new();
        procs_data.push(event_type::EV_PROCS_CHANGE);
        write_varint(&mut procs_data, 0); // dt = 0
        write_varint(&mut procs_data, num_workers); // number of Ps
        write_varint(&mut procs_data, 0); // stack ID

        output.push(event_type::EV_EVENT_BATCH);
        write_varint(&mut output, 1); // generation = 1
        write_varint(&mut output, 0); // M = 0 (not -1)
        write_varint(&mut output, base_timestamp); // base timestamp
        write_varint(&mut output, procs_data.len() as u64);
        output.extend_from_slice(&procs_data);

        // === For each worker M, emit a batch with ProcStart to associate P with M ===
        // ProcStart: dt, P ID, P seq - this puts P on the current M
        for &worker_id in &worker_ids {
            let mut start_data = Vec::new();
            start_data.push(event_type::EV_PROC_START);
            write_varint(&mut start_data, 0); // dt = 0
            write_varint(&mut start_data, worker_id as u64); // P ID = worker_id
            write_varint(&mut start_data, 0); // P seq = 0

            output.push(event_type::EV_EVENT_BATCH);
            write_varint(&mut output, 1); // generation = 1
            write_varint(&mut output, worker_id as u64); // M = worker_id
            write_varint(&mut output, base_timestamp); // base timestamp
            write_varint(&mut output, start_data.len() as u64);
            output.extend_from_slice(&start_data);
        }

        // Since we may not have TaskSpawn events for all goroutines (dial9 might only
        // send PollStart), we need to emit GoCreate for each unique goroutine we've seen
        // before writing the main event batch.
        let mut create_data = Vec::new();
        let mut sorted_tasks: Vec<_> = self.task_id_map.iter().collect();
        sorted_tasks.sort_by_key(|(_, &g_id)| g_id);
        for (_, &g_id) in sorted_tasks {
            // GoCreate: dt, new_g, new_stack, stack
            create_data.push(event_type::EV_GO_CREATE);
            write_varint(&mut create_data, 0); // dt = 0
            write_varint(&mut create_data, g_id); // goroutine ID
            write_varint(&mut create_data, 0); // new_stack (no stack info)
            write_varint(&mut create_data, 0); // creator stack (no stack info)
        }

        if !create_data.is_empty() {
            output.push(event_type::EV_EVENT_BATCH);
            write_varint(&mut output, 1); // generation = 1
            write_varint(&mut output, 0); // M = 0
            write_varint(&mut output, base_timestamp); // base timestamp
            write_varint(&mut output, create_data.len() as u64);
            output.extend_from_slice(&create_data);
        }

        // Write string table
        self.write_string_table(&mut output);

        // Write all events in a single batch on M=0 to ensure causal ordering
        // Sort events with custom ordering:
        // 1. TaskSpawn events first (GoCreate must come before GoStart for same goroutine)
        // 2. Then other events by timestamp
        let mut all_events: Vec<&OwnedEvent> = events.iter().collect();
        all_events.sort_by(|a, b| {
            // TaskSpawn events come first
            let a_is_spawn = matches!(a, OwnedEvent::TaskSpawn { .. });
            let b_is_spawn = matches!(b, OwnedEvent::TaskSpawn { .. });
            match (a_is_spawn, b_is_spawn) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.timestamp_nanos().cmp(&b.timestamp_nanos()),
            }
        });
        let owned_events: Vec<OwnedEvent> = all_events.into_iter().cloned().collect();

        self.write_event_batch(
            &mut output,
            0, // Use M=0 for all events
            &owned_events,
            base_timestamp,
            min_event_timestamp,
        );

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
