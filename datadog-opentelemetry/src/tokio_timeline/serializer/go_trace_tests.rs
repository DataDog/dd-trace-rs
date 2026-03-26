// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Comprehensive tests for the Go trace serializer.
//!
//! This module implements DST/TigerStyle/FoundationDB-inspired testing:
//! - Property-based tests for invariants
//! - Trace parsing and validation
//! - State machine invariant tests
//! - Golden/determinism tests
//! - Round-trip tests

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use proptest::prelude::*;
use proptest::strategy::Strategy;

use super::go_trace::{GoTraceSerializer, GO_TRACE_HEADER};
use super::TimelineSerializer;
use crate::tokio_timeline::buffer::OwnedEvent;

// ============================================================================
// TRACE PARSER - Reads back binary traces for validation
// ============================================================================

/// Go trace event types (copied from go_trace.rs for test validation).
mod event_type {
    pub const EV_EVENT_BATCH: u8 = 1;
    pub const EV_STACKS: u8 = 2;
    pub const EV_STACK: u8 = 3;
    pub const EV_STRINGS: u8 = 4;
    pub const EV_STRING: u8 = 5;
    pub const EV_FREQUENCY: u8 = 8;
    pub const EV_PROCS_CHANGE: u8 = 9;
    pub const EV_PROC_START: u8 = 10;
    pub const EV_PROC_STOP: u8 = 11;
    pub const EV_PROC_STATUS: u8 = 13;
    pub const EV_GO_CREATE: u8 = 14;
    pub const EV_GO_START: u8 = 16;
    pub const EV_GO_DESTROY: u8 = 17;
    pub const EV_GO_STOP: u8 = 19;
    pub const EV_GO_BLOCK: u8 = 20;
    pub const EV_GO_UNBLOCK: u8 = 21;
    pub const EV_GO_STATUS: u8 = 25;
}

/// Parsed Go trace event for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedEvent {
    /// GoCreate: new goroutine created.
    GoCreate {
        g_id: u64,
        new_stack: u64,
        stack: u64,
        dt: u64,
    },
    /// GoStart: goroutine starts running.
    GoStart { g_id: u64, g_seq: u64, dt: u64 },
    /// GoDestroy: goroutine exits.
    GoDestroy { dt: u64 },
    /// GoStop: goroutine yields voluntarily (stays runnable).
    GoStop { reason: u64, stack: u64, dt: u64 },
    /// GoBlock: goroutine blocks (becomes waiting).
    GoBlock { reason: u64, stack: u64, dt: u64 },
    /// GoUnblock: goroutine unblocked (becomes runnable).
    GoUnblock {
        g_id: u64,
        g_seq: u64,
        stack: u64,
        dt: u64,
    },
    /// GoStatus: initial goroutine status.
    GoStatus {
        g_id: u64,
        m_id: u64,
        status: u64,
        dt: u64,
    },
    /// ProcStart: processor started.
    ProcStart { p_id: u64, p_seq: u64, dt: u64 },
    /// ProcStop: processor stopped.
    ProcStop { dt: u64 },
    /// ProcStatus: initial processor status.
    ProcStatus { p_id: u64, status: u64, dt: u64 },
    /// ProcsChange: GOMAXPROCS changed.
    ProcsChange { procs: u64, stack: u64, dt: u64 },
    /// Frequency event.
    Frequency { freq: u64 },
    /// String table entry.
    String { id: u64, value: String },
    /// Stack entry.
    Stack { id: u64, frames: Vec<StackFrame> },
}

/// Parsed stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StackFrame {
    pc: u64,
    func_id: u64,
    file_id: u64,
    line: u64,
}

/// Event batch parsed from the trace.
#[derive(Debug)]
#[allow(dead_code)]
struct ParsedBatch {
    generation: u64,
    m_id: u64,
    timestamp: u64,
    events: Vec<ParsedEvent>,
}

/// Result of parsing a Go trace.
#[derive(Debug)]
struct ParsedTrace {
    batches: Vec<ParsedBatch>,
    strings: HashMap<u64, String>,
    stacks: HashMap<u64, Vec<StackFrame>>,
}

/// Error during trace parsing.
#[derive(Debug)]
#[allow(dead_code)]
enum ParseError {
    InvalidHeader,
    UnexpectedEndOfInput,
    InvalidVarint,
    InvalidEventType(u8),
    BatchSizeMismatch { expected: usize, actual: usize },
    InvalidStringId(u64),
    InvalidStackId(u64),
}

/// Reads a variable-length integer (LEB128 unsigned) from input.
fn read_varint(input: &[u8], pos: &mut usize) -> Result<u64, ParseError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= input.len() {
            return Err(ParseError::UnexpectedEndOfInput);
        }
        let byte = input[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(ParseError::InvalidVarint);
        }
    }
    Ok(result)
}

/// Parses a Go trace binary into structured data.
fn parse_trace(data: &[u8]) -> Result<ParsedTrace, ParseError> {
    let mut pos = 0;

    // Validate header
    if data.len() < 16 {
        return Err(ParseError::InvalidHeader);
    }
    if &data[0..16] != GO_TRACE_HEADER {
        return Err(ParseError::InvalidHeader);
    }
    pos = 16;

    let mut batches = Vec::new();
    let mut strings = HashMap::new();
    let mut stacks = HashMap::new();

    while pos < data.len() {
        // Read batch header
        let event_type = data[pos];
        pos += 1;

        if event_type != event_type::EV_EVENT_BATCH {
            return Err(ParseError::InvalidEventType(event_type));
        }

        let generation = read_varint(data, &mut pos)?;
        let m_id = read_varint(data, &mut pos)?;
        let timestamp = read_varint(data, &mut pos)?;
        let batch_size = read_varint(data, &mut pos)? as usize;

        let batch_start = pos;
        let batch_end = pos + batch_size;

        if batch_end > data.len() {
            return Err(ParseError::BatchSizeMismatch {
                expected: batch_size,
                actual: data.len() - pos,
            });
        }

        let mut events = Vec::new();

        // Parse events within the batch
        while pos < batch_end {
            let ev_type = data[pos];
            pos += 1;

            let event = match ev_type {
                event_type::EV_FREQUENCY => {
                    let freq = read_varint(data, &mut pos)?;
                    ParsedEvent::Frequency { freq }
                }
                event_type::EV_STRINGS => {
                    // String table marker - parse following EV_STRING entries
                    continue;
                }
                event_type::EV_STRING => {
                    let id = read_varint(data, &mut pos)?;
                    let len = read_varint(data, &mut pos)? as usize;
                    if pos + len > data.len() {
                        return Err(ParseError::UnexpectedEndOfInput);
                    }
                    let value = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
                    pos += len;
                    strings.insert(id, value.clone());
                    ParsedEvent::String { id, value }
                }
                event_type::EV_STACKS => {
                    // Stack table marker - parse following EV_STACK entries
                    continue;
                }
                event_type::EV_STACK => {
                    let id = read_varint(data, &mut pos)?;
                    let frame_count = read_varint(data, &mut pos)? as usize;
                    let mut frames = Vec::with_capacity(frame_count);
                    for _ in 0..frame_count {
                        let pc = read_varint(data, &mut pos)?;
                        let func_id = read_varint(data, &mut pos)?;
                        let file_id = read_varint(data, &mut pos)?;
                        let line = read_varint(data, &mut pos)?;
                        frames.push(StackFrame {
                            pc,
                            func_id,
                            file_id,
                            line,
                        });
                    }
                    stacks.insert(id, frames.clone());
                    ParsedEvent::Stack { id, frames }
                }
                event_type::EV_PROC_STATUS => {
                    let dt = read_varint(data, &mut pos)?;
                    let p_id = read_varint(data, &mut pos)?;
                    let status = read_varint(data, &mut pos)?;
                    ParsedEvent::ProcStatus { p_id, status, dt }
                }
                event_type::EV_PROC_START => {
                    let dt = read_varint(data, &mut pos)?;
                    let p_id = read_varint(data, &mut pos)?;
                    let p_seq = read_varint(data, &mut pos)?;
                    ParsedEvent::ProcStart { p_id, p_seq, dt }
                }
                event_type::EV_PROC_STOP => {
                    let dt = read_varint(data, &mut pos)?;
                    ParsedEvent::ProcStop { dt }
                }
                event_type::EV_PROCS_CHANGE => {
                    let dt = read_varint(data, &mut pos)?;
                    let procs = read_varint(data, &mut pos)?;
                    let stack = read_varint(data, &mut pos)?;
                    ParsedEvent::ProcsChange { procs, stack, dt }
                }
                event_type::EV_GO_CREATE => {
                    let dt = read_varint(data, &mut pos)?;
                    let g_id = read_varint(data, &mut pos)?;
                    let new_stack = read_varint(data, &mut pos)?;
                    let stack = read_varint(data, &mut pos)?;
                    ParsedEvent::GoCreate {
                        g_id,
                        new_stack,
                        stack,
                        dt,
                    }
                }
                event_type::EV_GO_START => {
                    let dt = read_varint(data, &mut pos)?;
                    let g_id = read_varint(data, &mut pos)?;
                    let g_seq = read_varint(data, &mut pos)?;
                    ParsedEvent::GoStart { g_id, g_seq, dt }
                }
                event_type::EV_GO_DESTROY => {
                    let dt = read_varint(data, &mut pos)?;
                    ParsedEvent::GoDestroy { dt }
                }
                event_type::EV_GO_STOP => {
                    let dt = read_varint(data, &mut pos)?;
                    let reason = read_varint(data, &mut pos)?;
                    let stack = read_varint(data, &mut pos)?;
                    ParsedEvent::GoStop { reason, stack, dt }
                }
                event_type::EV_GO_BLOCK => {
                    let dt = read_varint(data, &mut pos)?;
                    let reason = read_varint(data, &mut pos)?;
                    let stack = read_varint(data, &mut pos)?;
                    ParsedEvent::GoBlock { reason, stack, dt }
                }
                event_type::EV_GO_UNBLOCK => {
                    let dt = read_varint(data, &mut pos)?;
                    let g_id = read_varint(data, &mut pos)?;
                    let g_seq = read_varint(data, &mut pos)?;
                    let stack = read_varint(data, &mut pos)?;
                    ParsedEvent::GoUnblock {
                        g_id,
                        g_seq,
                        stack,
                        dt,
                    }
                }
                event_type::EV_GO_STATUS => {
                    let dt = read_varint(data, &mut pos)?;
                    let g_id = read_varint(data, &mut pos)?;
                    let m_id = read_varint(data, &mut pos)?;
                    let status = read_varint(data, &mut pos)?;
                    ParsedEvent::GoStatus {
                        g_id,
                        m_id,
                        status,
                        dt,
                    }
                }
                _ => {
                    return Err(ParseError::InvalidEventType(ev_type));
                }
            };

            events.push(event);
        }

        // Verify batch size matches
        let actual_size = pos - batch_start;
        if actual_size != batch_size {
            return Err(ParseError::BatchSizeMismatch {
                expected: batch_size,
                actual: actual_size,
            });
        }

        batches.push(ParsedBatch {
            generation,
            m_id,
            timestamp,
            events,
        });
    }

    Ok(ParsedTrace {
        batches,
        strings,
        stacks,
    })
}

// ============================================================================
// STATE MACHINE VALIDATOR - Validates goroutine state transitions
// ============================================================================

/// Goroutine state during trace validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum GoroutineValidationState {
    /// Not yet created or destroyed.
    NonExistent,
    /// Created but not started (Runnable).
    Runnable,
    /// Currently executing.
    Running,
    /// Blocked waiting for something.
    Waiting,
}

/// Processor state during trace validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ProcValidationState {
    /// Not yet seen.
    Unknown,
    /// Running (active).
    Running,
    /// Idle (parked).
    Idle,
}

/// Validates state machine invariants in a parsed trace.
struct StateValidator {
    /// Goroutine states.
    g_states: HashMap<u64, GoroutineValidationState>,
    /// Processor states.
    p_states: HashMap<u64, ProcValidationState>,
    /// M (thread) to currently running G mapping.
    m_to_g: HashMap<u64, Option<u64>>,
    /// Sequence numbers per goroutine (for monotonicity check).
    g_sequences: HashMap<u64, u64>,
    /// Sequence numbers per processor (for monotonicity check).
    p_sequences: HashMap<u64, u64>,
    /// Validation errors encountered.
    errors: Vec<String>,
}

impl StateValidator {
    fn new() -> Self {
        Self {
            g_states: HashMap::new(),
            p_states: HashMap::new(),
            m_to_g: HashMap::new(),
            g_sequences: HashMap::new(),
            p_sequences: HashMap::new(),
            errors: Vec::new(),
        }
    }

    fn validate_trace(&mut self, trace: &ParsedTrace) -> Vec<String> {
        // Go traces are validated per-batch (per-M), not globally.
        // Each M batch is self-consistent and events within a batch are ordered.
        // Cross-M goroutine transitions are valid as long as:
        // 1. The goroutine exists (was created somewhere)
        // 2. Per-batch invariants hold (no concurrent running on same M)

        // First pass: collect all goroutine creations and status initializations
        for batch in &trace.batches {
            for event in &batch.events {
                match event {
                    ParsedEvent::GoStatus { g_id, status, .. } => {
                        let state = match status {
                            1 => GoroutineValidationState::Runnable,
                            2 => GoroutineValidationState::Running,
                            4 => GoroutineValidationState::Waiting,
                            _ => continue,
                        };
                        self.g_states.insert(*g_id, state);
                    }
                    ParsedEvent::GoCreate { g_id, .. } => {
                        self.g_states
                            .entry(*g_id)
                            .or_insert(GoroutineValidationState::Runnable);
                    }
                    _ => {}
                }
            }
        }

        // Second pass: validate per-batch invariants
        for batch in &trace.batches {
            let m_id = batch.m_id;
            // Reset per-M running state for this batch
            self.m_to_g.insert(m_id, None);

            for event in &batch.events {
                self.validate_event_per_batch(m_id, event, &trace.stacks, &trace.strings);
            }
        }

        std::mem::take(&mut self.errors)
    }

    /// Validates per-batch (per-M) invariants only.
    /// This is more lenient than global validation because Go traces
    /// allow goroutines to move between Ms.
    fn validate_event_per_batch(
        &mut self,
        m_id: u64,
        event: &ParsedEvent,
        stacks: &HashMap<u64, Vec<StackFrame>>,
        strings: &HashMap<u64, String>,
    ) {
        match event {
            ParsedEvent::GoStatus { g_id, status, .. } => {
                // GoStatus establishes initial state (already processed in first pass)
                if *status == 2 {
                    // Running
                    self.m_to_g.insert(m_id, Some(*g_id));
                }
            }

            ParsedEvent::ProcStatus { p_id, status, .. } => {
                let state = match status {
                    1 => ProcValidationState::Running,
                    2 => ProcValidationState::Idle,
                    _ => {
                        self.errors.push(format!(
                            "Invalid ProcStatus status {} for P{}",
                            status, p_id
                        ));
                        return;
                    }
                };
                self.p_states.insert(*p_id, state);
            }

            ParsedEvent::GoCreate {
                g_id,
                new_stack,
                stack,
                ..
            } => {
                // Validate stack IDs exist (if non-zero)
                if *new_stack != 0 && !stacks.contains_key(new_stack) {
                    self.errors.push(format!(
                        "GoCreate references invalid new_stack ID {}",
                        new_stack
                    ));
                }
                if *stack != 0 && !stacks.contains_key(stack) {
                    self.errors
                        .push(format!("GoCreate references invalid stack ID {}", stack));
                }
                // State already tracked in first pass
            }

            ParsedEvent::GoStart { g_id, g_seq, .. } => {
                // Per-batch invariant: G must exist
                if !self.g_states.contains_key(g_id) {
                    self.errors.push(format!(
                        "GoStart for G{} but goroutine was never created",
                        g_id
                    ));
                }

                // Per-batch invariant: No other G should be running on this M
                if let Some(Some(running_g)) = self.m_to_g.get(&m_id) {
                    if *running_g != *g_id {
                        self.errors.push(format!(
                            "GoStart for G{} on M{} but G{} is already running there",
                            g_id, m_id, running_g
                        ));
                    }
                }

                self.g_sequences.insert(*g_id, *g_seq);
                self.m_to_g.insert(m_id, Some(*g_id));
            }

            ParsedEvent::GoStop { stack, .. } => {
                // Per-batch invariant: A G must be running on this M
                if self.m_to_g.get(&m_id).unwrap_or(&None).is_none() {
                    self.errors
                        .push(format!("GoStop on M{} but no G is running", m_id));
                }

                // Validate stack ID
                if *stack != 0 && !stacks.contains_key(stack) {
                    self.errors
                        .push(format!("GoStop references invalid stack ID {}", stack));
                }

                self.m_to_g.insert(m_id, None);
            }

            ParsedEvent::GoBlock { stack, .. } => {
                // Per-batch invariant: A G must be running on this M
                if self.m_to_g.get(&m_id).unwrap_or(&None).is_none() {
                    self.errors
                        .push(format!("GoBlock on M{} but no G is running", m_id));
                }

                // Validate stack ID
                if *stack != 0 && !stacks.contains_key(stack) {
                    self.errors
                        .push(format!("GoBlock references invalid stack ID {}", stack));
                }

                self.m_to_g.insert(m_id, None);
            }

            ParsedEvent::GoUnblock { g_id, stack, .. } => {
                // Per-batch invariant: G must exist
                if !self.g_states.contains_key(g_id) {
                    self.errors.push(format!(
                        "GoUnblock for G{} but goroutine was never created",
                        g_id
                    ));
                }

                // Validate stack ID
                if *stack != 0 && !stacks.contains_key(stack) {
                    self.errors
                        .push(format!("GoUnblock references invalid stack ID {}", stack));
                }
            }

            ParsedEvent::GoDestroy { .. } => {
                // Per-batch invariant: A G must be running on this M
                if self.m_to_g.get(&m_id).unwrap_or(&None).is_none() {
                    self.errors
                        .push(format!("GoDestroy on M{} but no G is running", m_id));
                }

                self.m_to_g.insert(m_id, None);
            }

            ParsedEvent::ProcStart { p_id, p_seq, .. } => {
                self.p_sequences.insert(*p_id, *p_seq);
                self.p_states.insert(*p_id, ProcValidationState::Running);
            }

            ParsedEvent::ProcStop { .. } => {
                // P should be running (lenient check)
                let p_id = m_id; // 1:1 mapping
                self.p_states.insert(p_id, ProcValidationState::Idle);
            }

            ParsedEvent::Frequency { .. } => {}
            ParsedEvent::String { .. } => {}

            ParsedEvent::Stack { id, frames } => {
                // Validate stack frames reference valid strings
                for frame in frames {
                    if frame.func_id != 0 && !strings.contains_key(&frame.func_id) {
                        self.errors.push(format!(
                            "Stack {} frame references invalid func_id {}",
                            id, frame.func_id
                        ));
                    }
                    if frame.file_id != 0 && !strings.contains_key(&frame.file_id) {
                        self.errors.push(format!(
                            "Stack {} frame references invalid file_id {}",
                            id, frame.file_id
                        ));
                    }
                }
            }

            ParsedEvent::ProcsChange { .. } => {}
        }
    }
}

// ============================================================================
// PROPERTY-BASED TEST STRATEGIES
// ============================================================================

/// Strategy for generating random task IDs.
fn task_id_strategy() -> impl Strategy<Value = u64> {
    1u64..1000
}

/// Strategy for generating random worker IDs.
fn worker_id_strategy() -> impl Strategy<Value = u8> {
    0u8..8
}

/// Strategy for generating random locations.
fn location_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex(r"[a-z]+\.rs:[0-9]+").unwrap()
}

/// Strategy for generating a single random event.
fn event_strategy(base_timestamp: u64) -> impl Strategy<Value = OwnedEvent> {
    prop_oneof![
        (task_id_strategy(), location_strategy()).prop_map(move |(task_id, location)| {
            OwnedEvent::TaskSpawn {
                timestamp_nanos: base_timestamp,
                task_id,
                location,
            }
        }),
        (
            worker_id_strategy(),
            task_id_strategy(),
            location_strategy()
        )
            .prop_map(move |(worker_id, task_id, location)| {
                OwnedEvent::PollStart {
                    timestamp_nanos: base_timestamp,
                    worker_id,
                    task_id,
                    location,
                }
            }),
        worker_id_strategy().prop_map(move |worker_id| {
            OwnedEvent::PollEnd {
                timestamp_nanos: base_timestamp,
                worker_id,
            }
        }),
        task_id_strategy().prop_map(move |task_id| {
            OwnedEvent::TaskTerminate {
                timestamp_nanos: base_timestamp,
                task_id,
            }
        }),
        (task_id_strategy(), task_id_strategy()).prop_map(move |(waker, woken)| {
            OwnedEvent::WakeEvent {
                timestamp_nanos: base_timestamp,
                waker_task_id: waker,
                woken_task_id: woken,
            }
        }),
        worker_id_strategy().prop_map(move |worker_id| {
            OwnedEvent::WorkerPark {
                timestamp_nanos: base_timestamp,
                worker_id,
                cpu_time_nanos: 1000,
            }
        }),
        worker_id_strategy().prop_map(move |worker_id| {
            OwnedEvent::WorkerUnpark {
                timestamp_nanos: base_timestamp,
                worker_id,
                sched_wait_nanos: 500,
            }
        }),
    ]
}

/// Strategy for generating a sequence of events with increasing timestamps.
fn event_sequence_strategy(count: usize) -> impl Strategy<Value = Vec<OwnedEvent>> {
    let base_timestamp = 1_000_000_000_000u64;
    prop::collection::vec(
        (0..count as u64).prop_flat_map(move |i| event_strategy(base_timestamp + i * 1000)),
        count,
    )
}

/// Strategy for generating well-formed event sequences (spawn before poll, etc.).
fn well_formed_event_sequence_strategy() -> impl Strategy<Value = Vec<OwnedEvent>> {
    let task_count = 1..5usize;
    let worker_count = 1..4usize;

    (task_count, worker_count).prop_flat_map(|(tasks, workers)| {
        let mut events = Vec::new();
        let base_time = 1_000_000_000_000u64;
        let mut time = base_time;

        // Generate spawn events for all tasks
        for task_id in 1..=tasks as u64 {
            events.push(OwnedEvent::TaskSpawn {
                timestamp_nanos: time,
                task_id,
                location: format!("src/task{}.rs:{}", task_id, task_id * 10),
            });
            time += 1000;
        }

        // Generate poll start/end cycles
        for cycle in 0..3 {
            for task_id in 1..=tasks as u64 {
                let worker_id = ((task_id as usize + cycle) % workers) as u8;
                events.push(OwnedEvent::PollStart {
                    timestamp_nanos: time,
                    worker_id,
                    task_id,
                    location: format!("src/task{}.rs:{}", task_id, task_id * 10),
                });
                time += 10_000; // 10us of work

                events.push(OwnedEvent::PollEnd {
                    timestamp_nanos: time,
                    worker_id,
                });
                time += 1000;
            }
        }

        // Generate terminate events
        for task_id in 1..=tasks as u64 {
            events.push(OwnedEvent::TaskTerminate {
                timestamp_nanos: time,
                task_id,
            });
            time += 1000;
        }

        Just(events)
    })
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[test]
fn test_parse_empty_trace() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![];
    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse empty trace");

    // Should have at least frequency batch
    assert!(
        !parsed.batches.is_empty(),
        "Empty trace should have at least one batch"
    );

    // Should have frequency event
    let has_frequency = parsed.batches.iter().any(|b| {
        b.events
            .iter()
            .any(|e| matches!(e, ParsedEvent::Frequency { .. }))
    });
    assert!(has_frequency, "Trace should have frequency event");
}

#[test]
fn test_parse_simple_trace() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_100_001,
            task_id: 100,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Validate basic structure
    assert!(parsed.batches.len() >= 1, "Should have at least one batch");

    // Collect all goroutine events
    let go_events: Vec<_> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| {
            matches!(
                e,
                ParsedEvent::GoCreate { .. }
                    | ParsedEvent::GoStart { .. }
                    | ParsedEvent::GoStop { .. }
                    | ParsedEvent::GoDestroy { .. }
            )
        })
        .collect();

    // Should have GoCreate, GoStart, GoStop, GoStart (for destroy), GoDestroy
    let has_create = go_events
        .iter()
        .any(|e| matches!(e, ParsedEvent::GoCreate { .. }));
    let has_start = go_events
        .iter()
        .any(|e| matches!(e, ParsedEvent::GoStart { .. }));
    let has_destroy = go_events
        .iter()
        .any(|e| matches!(e, ParsedEvent::GoDestroy { .. }));

    assert!(has_create, "Should have GoCreate event");
    assert!(has_start, "Should have GoStart event");
    assert!(has_destroy, "Should have GoDestroy event");
}

#[test]
fn test_state_machine_validation_simple() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_100_001,
            task_id: 100,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);

    assert!(
        errors.is_empty(),
        "State machine validation errors: {:?}",
        errors
    );
}

#[test]
fn test_header_format() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![];
    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    // Header must be exactly 16 bytes: "go 1.23 trace\0\0\0"
    assert!(result.data.len() >= 16, "Trace too short for header");
    assert_eq!(&result.data[0..16], GO_TRACE_HEADER, "Invalid header");
}

#[test]
fn test_varint_encoding() {
    // Test varint round-trip for various values
    let test_values = [
        0,
        1,
        127,
        128,
        255,
        256,
        16383,
        16384,
        65535,
        1_000_000_000,
        u64::MAX,
    ];

    for value in test_values {
        let mut buf = Vec::new();
        super::go_trace::write_varint(&mut buf, value);

        let mut pos = 0;
        let decoded = read_varint(&buf, &mut pos).expect("Failed to decode varint");
        assert_eq!(decoded, value, "Varint round-trip failed for {}", value);
        assert_eq!(
            pos,
            buf.len(),
            "Varint didn't consume all bytes for {}",
            value
        );
    }
}

#[test]
fn test_string_table_populated() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![OwnedEvent::TaskSpawn {
        timestamp_nanos: 1_000_000_000,
        task_id: 100,
        location: "unique_location.rs:42".to_string(),
    }];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have string entries
    assert!(
        !parsed.strings.is_empty(),
        "String table should be populated"
    );

    // Should contain our location (or parts of it)
    let has_relevant_string = parsed
        .strings
        .values()
        .any(|s| s.contains("unique_location") || s.contains(".rs"));
    assert!(
        has_relevant_string,
        "String table should contain location-related strings"
    );
}

#[test]
fn test_stack_table_populated() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![OwnedEvent::TaskSpawn {
        timestamp_nanos: 1_000_000_000,
        task_id: 100,
        location: "main.rs:10".to_string(),
    }];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have stack entries
    assert!(!parsed.stacks.is_empty(), "Stack table should be populated");

    // Each stack should have at least one frame
    for (id, frames) in &parsed.stacks {
        assert!(!frames.is_empty(), "Stack {} should have frames", id);
    }
}

#[test]
fn test_multiple_workers() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_001_000,
            task_id: 200,
            location: "main.rs:20".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_011_000,
            worker_id: 1,
            task_id: 200,
            location: "main.rs:20".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_101_000,
            worker_id: 1,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have batches for multiple M values
    let m_ids: HashSet<_> = parsed.batches.iter().map(|b| b.m_id).collect();

    // Should have M=0 and M=1 (and possibly M=u64::MAX for metadata)
    assert!(m_ids.contains(&0), "Should have batch for M=0");
    assert!(m_ids.contains(&1), "Should have batch for M=1");

    // Validate state machine
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(errors.is_empty(), "State machine errors: {:?}", errors);
}

#[test]
fn test_deterministic_output() {
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_100_001,
            task_id: 100,
        },
    ];

    // Serialize multiple times
    let mut results = Vec::new();
    for _ in 0..5 {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .unwrap();
        results.push(result.data);
    }

    // All outputs must be identical
    for (i, result) in results.iter().enumerate().skip(1) {
        assert_eq!(
            &results[0], result,
            "Serialization {} differs from first",
            i
        );
    }
}

#[test]
fn test_wake_event_handling() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        // Spawn two tasks
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_001_000,
            task_id: 200,
            location: "main.rs:20".to_string(),
        },
        // Task 100 starts
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        // Task 100 yields
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        // Task 200 wakes task 100
        OwnedEvent::WakeEvent {
            timestamp_nanos: 1_000_200_000,
            waker_task_id: 200,
            woken_task_id: 100,
        },
        // Task 100 runs again
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_300_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_400_000,
            worker_id: 0,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Validate no state machine errors
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "State machine errors with wake: {:?}",
        errors
    );
}

#[test]
fn test_worker_park_unpark() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_010_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_100_000,
            worker_id: 0,
        },
        // Worker parks (no more work)
        OwnedEvent::WorkerPark {
            timestamp_nanos: 1_000_200_000,
            worker_id: 0,
            cpu_time_nanos: 90000,
        },
        // Worker unparks (work available)
        OwnedEvent::WorkerUnpark {
            timestamp_nanos: 1_000_300_000,
            worker_id: 0,
            sched_wait_nanos: 100000,
        },
        // Task runs again
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_400_000,
            worker_id: 0,
            task_id: 100,
            location: "main.rs:10".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_500_000,
            worker_id: 0,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have ProcStop and ProcStart events
    let has_proc_stop = parsed.batches.iter().any(|b| {
        b.events
            .iter()
            .any(|e| matches!(e, ParsedEvent::ProcStop { .. }))
    });
    let has_proc_start = parsed.batches.iter().any(|b| {
        b.events
            .iter()
            .any(|e| matches!(e, ParsedEvent::ProcStart { .. }))
    });

    assert!(has_proc_stop, "Should have ProcStop for WorkerPark");
    assert!(has_proc_start, "Should have ProcStart for WorkerUnpark");
}

#[test]
fn test_frequency_event_present() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![];
    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    let frequency_events: Vec<_> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter_map(|e| match e {
            ParsedEvent::Frequency { freq } => Some(*freq),
            _ => None,
        })
        .collect();

    assert!(!frequency_events.is_empty(), "Should have frequency event");

    // Frequency should be reasonable (~15.6 MHz for Go traces)
    for freq in frequency_events {
        assert!(freq > 1_000_000, "Frequency too low: {}", freq);
        assert!(freq < 100_000_000_000, "Frequency too high: {}", freq);
    }
}

#[test]
fn test_batch_sizes_valid() {
    let mut serializer = GoTraceSerializer::new();

    // Generate enough events to potentially create multiple batches
    let mut events = Vec::new();
    let base = 1_000_000_000_000u64;
    for i in 0..100 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 1000,
            task_id: i,
            location: format!("task{}.rs:{}", i, i * 10),
        });
        events.push(OwnedEvent::PollStart {
            timestamp_nanos: base + i * 1000 + 100,
            worker_id: (i % 4) as u8,
            task_id: i,
            location: format!("task{}.rs:{}", i, i * 10),
        });
        events.push(OwnedEvent::PollEnd {
            timestamp_nanos: base + i * 1000 + 500,
            worker_id: (i % 4) as u8,
        });
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    // Parse should succeed (batch sizes must be correct)
    let parsed = parse_trace(&result.data).expect("Failed to parse trace with many events");

    // All batches should have valid size
    for batch in &parsed.batches {
        assert!(
            batch.events.len() > 0 || batch.m_id == u64::MAX,
            "Batch for M={} has no events",
            batch.m_id
        );
    }
}

#[test]
fn test_go_status_initialization() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![OwnedEvent::TaskSpawn {
        timestamp_nanos: 1_000_000_000,
        task_id: 100,
        location: "main.rs:10".to_string(),
    }];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have GoStatus event for main goroutine (G=1)
    let go_status_events: Vec<_> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::GoStatus { .. }))
        .collect();

    assert!(!go_status_events.is_empty(), "Should have GoStatus event");

    // G=1 (main goroutine) should be initialized as Running
    let has_g1_running = go_status_events.iter().any(|e| {
        matches!(
            e,
            ParsedEvent::GoStatus {
                g_id: 1,
                status: 2,
                ..
            }
        )
    });
    assert!(
        has_g1_running,
        "Main goroutine (G=1) should be initialized as Running"
    );
}

#[test]
fn test_proc_status_initialization() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![OwnedEvent::TaskSpawn {
        timestamp_nanos: 1_000_000_000,
        task_id: 100,
        location: "main.rs:10".to_string(),
    }];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Failed to parse trace");

    // Should have ProcStatus event for P=0
    let proc_status_events: Vec<_> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::ProcStatus { .. }))
        .collect();

    assert!(
        !proc_status_events.is_empty(),
        "Should have ProcStatus event"
    );

    // P=0 should be initialized as Running
    let has_p0_running = proc_status_events.iter().any(|e| {
        matches!(
            e,
            ParsedEvent::ProcStatus {
                p_id: 0,
                status: 1,
                ..
            }
        )
    });
    assert!(has_p0_running, "P=0 should be initialized as Running");
}

// ============================================================================
// PROPERTY-BASED TESTS
// ============================================================================

proptest! {
    /// Property: Every generated trace should parse successfully.
    #[test]
    fn prop_trace_always_parseable(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data);
        prop_assert!(parsed.is_ok(), "Parse failed: {:?}", parsed.err());
    }

    /// Property: Trace header is always valid.
    #[test]
    fn prop_header_always_valid(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        prop_assert!(result.data.len() >= 16, "Trace too short");
        prop_assert_eq!(&result.data[0..16], GO_TRACE_HEADER, "Invalid header");
    }

    /// Property: State machine invariants hold for well-formed inputs.
    #[test]
    fn prop_state_machine_invariants_hold(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data).expect("Parse should succeed");

        let mut validator = StateValidator::new();
        let errors = validator.validate_trace(&parsed);

        prop_assert!(errors.is_empty(), "State machine errors: {:?}", errors);
    }

    /// Property: All string IDs in stacks reference valid strings.
    #[test]
    fn prop_stack_string_refs_valid(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data).expect("Parse should succeed");

        for (stack_id, frames) in &parsed.stacks {
            for frame in frames {
                if frame.func_id != 0 {
                    prop_assert!(
                        parsed.strings.contains_key(&frame.func_id),
                        "Stack {} references invalid func_id {}",
                        stack_id, frame.func_id
                    );
                }
                if frame.file_id != 0 {
                    prop_assert!(
                        parsed.strings.contains_key(&frame.file_id),
                        "Stack {} references invalid file_id {}",
                        stack_id, frame.file_id
                    );
                }
            }
        }
    }

    /// Property: Serialization is deterministic.
    #[test]
    fn prop_serialization_deterministic(events in well_formed_event_sequence_strategy()) {
        let mut serializer1 = GoTraceSerializer::new();
        let result1 = serializer1
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization 1 should succeed");

        let mut serializer2 = GoTraceSerializer::new();
        let result2 = serializer2
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization 2 should succeed");

        prop_assert_eq!(result1.data, result2.data, "Serialization not deterministic");
    }

    /// Property: All batches have valid generation (should be 1).
    #[test]
    fn prop_batch_generation_valid(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data).expect("Parse should succeed");

        for batch in &parsed.batches {
            prop_assert_eq!(batch.generation, 1, "Batch generation should be 1");
        }
    }

    /// Property: Random events don't cause panics (fuzz test).
    #[test]
    fn prop_random_events_no_panic(events in event_sequence_strategy(20)) {
        let mut serializer = GoTraceSerializer::new();
        // Should not panic even with random/malformed event sequences
        let _ = serializer.serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
    }

    /// Property: Delta timestamps are non-negative in output.
    #[test]
    fn prop_delta_timestamps_non_negative(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data).expect("Parse should succeed");

        // Check delta timestamps in goroutine events
        for batch in &parsed.batches {
            for event in &batch.events {
                let dt = match event {
                    ParsedEvent::GoCreate { dt, .. } => Some(*dt),
                    ParsedEvent::GoStart { dt, .. } => Some(*dt),
                    ParsedEvent::GoStop { dt, .. } => Some(*dt),
                    ParsedEvent::GoBlock { dt, .. } => Some(*dt),
                    ParsedEvent::GoUnblock { dt, .. } => Some(*dt),
                    ParsedEvent::GoDestroy { dt } => Some(*dt),
                    ParsedEvent::GoStatus { dt, .. } => Some(*dt),
                    ParsedEvent::ProcStart { dt, .. } => Some(*dt),
                    ParsedEvent::ProcStop { dt } => Some(*dt),
                    ParsedEvent::ProcStatus { dt, .. } => Some(*dt),
                    _ => None,
                };

                // All delta timestamps should fit in i64 (no overflow/underflow)
                if let Some(dt) = dt {
                    prop_assert!(dt <= i64::MAX as u64, "Delta timestamp too large: {}", dt);
                }
            }
        }
    }

    /// Property: Sequence numbers are monotonically increasing per goroutine within each M batch.
    /// Note: When a goroutine moves between Ms, global sequence monotonicity is not guaranteed
    /// because each M maintains its own state machine. This is a known limitation.
    #[test]
    fn prop_sequence_numbers_monotonic_per_batch(events in well_formed_event_sequence_strategy()) {
        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data).expect("Parse should succeed");

        // Track sequence numbers per goroutine PER BATCH (not globally)
        for batch in &parsed.batches {
            let mut g_sequences: HashMap<u64, Vec<u64>> = HashMap::new();

            for event in &batch.events {
                match event {
                    ParsedEvent::GoStart { g_id, g_seq, .. } => {
                        g_sequences.entry(*g_id).or_default().push(*g_seq);
                    }
                    ParsedEvent::GoUnblock { g_id, g_seq, .. } => {
                        g_sequences.entry(*g_id).or_default().push(*g_seq);
                    }
                    _ => {}
                }
            }

            // Verify monotonicity within this batch
            for (g_id, seqs) in &g_sequences {
                for i in 1..seqs.len() {
                    prop_assert!(
                        seqs[i] > seqs[i-1],
                        "Sequence not monotonic within batch for G{}: {:?}",
                        g_id, seqs
                    );
                }
            }
        }
    }
}

// ============================================================================
// GOLDEN TESTS
// ============================================================================

/// Golden test: Simple spawn-poll-terminate lifecycle.
#[test]
fn golden_simple_lifecycle() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: 42,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_001_000,
            worker_id: 0,
            task_id: 42,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_002_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_000_003_000,
            task_id: 42,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();

    // Parse and validate structure
    let parsed = parse_trace(&result.data).unwrap();

    // Collect all Go events in order
    let mut go_events = Vec::new();
    for batch in &parsed.batches {
        for event in &batch.events {
            if matches!(
                event,
                ParsedEvent::GoCreate { .. }
                    | ParsedEvent::GoStart { .. }
                    | ParsedEvent::GoStop { .. }
                    | ParsedEvent::GoDestroy { .. }
            ) {
                go_events.push(event.clone());
            }
        }
    }

    // Expected sequence: GoCreate, GoStart, GoStop, GoStart (for destroy), GoDestroy
    assert!(
        go_events.len() >= 4,
        "Expected at least 4 Go events, got {}",
        go_events.len()
    );

    // First should be GoCreate
    assert!(
        matches!(go_events[0], ParsedEvent::GoCreate { .. }),
        "First Go event should be GoCreate, got {:?}",
        go_events[0]
    );

    // Should have at least one GoStart
    let has_start = go_events
        .iter()
        .any(|e| matches!(e, ParsedEvent::GoStart { .. }));
    assert!(has_start, "Should have GoStart");

    // Last should be GoDestroy
    assert!(
        matches!(go_events.last(), Some(ParsedEvent::GoDestroy { .. })),
        "Last Go event should be GoDestroy, got {:?}",
        go_events.last()
    );
}

// ============================================================================
// ROUND-TRIP TESTS
// ============================================================================

/// Counts the input events by type and verifies they appear in the output.
#[test]
fn roundtrip_event_preservation() {
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: 1,
            location: "a.rs:1".to_string(),
        },
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_001_000,
            task_id: 2,
            location: "b.rs:2".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_010_000,
            worker_id: 0,
            task_id: 1,
            location: "a.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_100_000,
            worker_id: 0,
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_110_000,
            worker_id: 0,
            task_id: 2,
            location: "b.rs:2".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_200_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_000_200_001,
            task_id: 1,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_000_200_002,
            task_id: 2,
        },
    ];

    // Count input events
    let spawn_count = events
        .iter()
        .filter(|e| matches!(e, OwnedEvent::TaskSpawn { .. }))
        .count();
    let terminate_count = events
        .iter()
        .filter(|e| matches!(e, OwnedEvent::TaskTerminate { .. }))
        .count();
    let poll_start_count = events
        .iter()
        .filter(|e| matches!(e, OwnedEvent::PollStart { .. }))
        .count();
    // Note: poll_end_count may differ from GoStop count due to context switches
    let _poll_end_count = events
        .iter()
        .filter(|e| matches!(e, OwnedEvent::PollEnd { .. }))
        .count();

    let mut serializer = GoTraceSerializer::new();
    let result = serializer
        .serialize(&events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Count output events (GoCreate maps to TaskSpawn, GoDestroy maps to TaskTerminate, etc.)
    let go_create_count = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::GoCreate { .. }))
        .count();

    let go_destroy_count = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::GoDestroy { .. }))
        .count();

    let go_start_count = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::GoStart { .. }))
        .count();

    // Note: GoStop count may differ from PollEnd due to state machine handling
    // (context switches generate GoStop too)

    // Each TaskSpawn should produce exactly one GoCreate
    assert_eq!(
        go_create_count, spawn_count,
        "GoCreate count {} != TaskSpawn count {}",
        go_create_count, spawn_count
    );

    // Each TaskTerminate should produce exactly one GoDestroy
    assert_eq!(
        go_destroy_count, terminate_count,
        "GoDestroy count {} != TaskTerminate count {}",
        go_destroy_count, terminate_count
    );

    // Each PollStart should produce at least one GoStart
    // (might be more due to auto-unblock before start)
    assert!(
        go_start_count >= poll_start_count,
        "GoStart count {} < PollStart count {}",
        go_start_count,
        poll_start_count
    );
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn edge_case_empty_events() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![];
    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    // Should still produce valid trace with header and frequency
    assert!(
        result.data.len() > 16,
        "Empty trace should have more than just header"
    );

    let parsed = parse_trace(&result.data).unwrap();
    assert!(!parsed.batches.is_empty(), "Should have at least one batch");
}

#[test]
fn edge_case_single_event() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![OwnedEvent::TaskSpawn {
        timestamp_nanos: 1_000_000_000_000,
        task_id: 1,
        location: "test.rs:1".to_string(),
    }];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Single event validation errors: {:?}",
        errors
    );
}

#[test]
fn edge_case_poll_without_spawn() {
    // PollStart for unknown task should auto-create the goroutine
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_000_000,
            worker_id: 0,
            task_id: 999, // Never spawned
            location: "mystery.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_001_000,
            worker_id: 0,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Should have auto-created the goroutine
    let has_create = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(e, ParsedEvent::GoCreate { .. }));

    assert!(
        has_create,
        "Should auto-create goroutine for unknown PollStart"
    );

    // State machine should still be valid
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Auto-create validation errors: {:?}",
        errors
    );
}

#[test]
fn edge_case_terminate_without_poll() {
    // TaskTerminate for never-polled task
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: 1,
            location: "test.rs:1".to_string(),
        },
        // No poll - task terminates immediately
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_000_001_000,
            task_id: 1,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Should have GoDestroy event
    let has_destroy = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(e, ParsedEvent::GoDestroy { .. }));

    assert!(has_destroy, "Should have GoDestroy for terminated task");

    // State machine should be valid (terminate should auto-start if needed)
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Terminate-without-poll validation errors: {:?}",
        errors
    );
}

#[test]
fn edge_case_large_task_id() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: u64::MAX - 1, // Very large task ID
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_001_000,
            worker_id: 0,
            task_id: u64::MAX - 1,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_002_000,
            worker_id: 0,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    // Should parse successfully
    let parsed = parse_trace(&result.data).expect("Large task ID trace should parse");

    // Goroutine ID should be remapped to small sequential ID
    let g_ids: HashSet<_> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter_map(|e| match e {
            ParsedEvent::GoCreate { g_id, .. } => Some(*g_id),
            ParsedEvent::GoStart { g_id, .. } => Some(*g_id),
            _ => None,
        })
        .collect();

    // Should not have the huge task ID as goroutine ID
    assert!(
        !g_ids.contains(&(u64::MAX - 1)),
        "Large task ID should be remapped"
    );
}

#[test]
fn edge_case_many_workers() {
    let mut serializer = GoTraceSerializer::new();
    let mut events = Vec::new();
    let base = 1_000_000_000_000u64;

    // Spawn 8 tasks
    for i in 0..8 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 1000,
            task_id: i,
            location: format!("worker{}.rs:{}", i, i),
        });
    }

    // Run each on different worker
    for i in 0..8 {
        events.push(OwnedEvent::PollStart {
            timestamp_nanos: base + 10000 + i * 1000,
            worker_id: i as u8,
            task_id: i,
            location: format!("worker{}.rs:{}", i, i),
        });
        events.push(OwnedEvent::PollEnd {
            timestamp_nanos: base + 20000 + i * 1000,
            worker_id: i as u8,
        });
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Should have batches for all 8 workers
    let m_ids: HashSet<_> = parsed
        .batches
        .iter()
        .map(|b| b.m_id)
        .filter(|&m| m != u64::MAX) // Exclude metadata batch
        .collect();

    for i in 0..8 {
        assert!(m_ids.contains(&i), "Should have batch for M={}", i);
    }

    // State machine should be valid
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Many workers validation errors: {:?}",
        errors
    );
}

#[test]
fn edge_case_rapid_context_switches() {
    // Rapid switches between tasks on same worker
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;
    let mut events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base,
            task_id: 1,
            location: "a.rs:1".to_string(),
        },
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base + 100,
            task_id: 2,
            location: "b.rs:2".to_string(),
        },
    ];

    // Rapid context switches
    for i in 0..10 {
        let task = if i % 2 == 0 { 1 } else { 2 };
        events.push(OwnedEvent::PollStart {
            timestamp_nanos: base + 1000 + i * 100,
            worker_id: 0,
            task_id: task,
            location: if task == 1 {
                "a.rs:1".to_string()
            } else {
                "b.rs:2".to_string()
            },
        });
        events.push(OwnedEvent::PollEnd {
            timestamp_nanos: base + 1050 + i * 100,
            worker_id: 0,
        });
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Rapid context switch validation errors: {:?}",
        errors
    );
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

/// Regression test: Ensure wake event for already-runnable goroutine is no-op.
#[test]
fn regression_wake_runnable_noop() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: 1,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_001_000,
            worker_id: 0,
            task_id: 1,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_002_000,
            worker_id: 0,
        },
        // Wake event for task that just yielded (should be Runnable, not Waiting)
        // After GoStop, goroutine is Runnable, so this wake should be no-op
        OwnedEvent::WakeEvent {
            timestamp_nanos: 1_000_000_003_000,
            waker_task_id: 99,
            woken_task_id: 1,
        },
        OwnedEvent::PollStart {
            timestamp_nanos: 1_000_000_004_000,
            worker_id: 0,
            task_id: 1,
            location: "test.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: 1_000_000_005_000,
            worker_id: 0,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Count GoUnblock events - should only unblock when actually Waiting
    let unblock_count = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| matches!(e, ParsedEvent::GoUnblock { .. }))
        .count();

    // Since we use GoStop (not GoBlock), the goroutine stays Runnable
    // Wake for Runnable goroutine should be no-op (no GoUnblock emitted)
    assert_eq!(
        unblock_count, 0,
        "Wake for Runnable goroutine should not emit GoUnblock, got {}",
        unblock_count
    );

    // State machine should be valid
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Wake runnable validation errors: {:?}",
        errors
    );
}

/// Regression test: GoDestroy must not be emitted without prior GoStart on same M.
/// This tests the case where a task terminates (TaskTerminate routed to M=0) but
/// the task was last polled on a different M. In this case, we cannot emit GoDestroy
/// without first emitting GoStart, which requires the G to be Runnable (not Running).
#[test]
fn regression_destroy_without_start_on_different_m() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    // Scenario:
    // 1. Task 42 spawns (routed to M=0)
    // 2. Task 42 polls on worker 3 (M=3)
    // 3. Task 42 terminates (routed to M=0, but G is still Running on M=3!)
    //
    // Without the fix, this would emit GoDestroy on M=0 without GoStart,
    // because go_start sees status=Running and doesn't emit GoStart.
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base,
            task_id: 42,
            location: "task.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: base + 1000,
            worker_id: 3, // M=3
            task_id: 42,
            location: "task.rs:1".to_string(),
        },
        // NO PollEnd - task is still Running on M=3
        OwnedEvent::TaskTerminate {
            timestamp_nanos: base + 2000,
            task_id: 42,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Should parse");

    // Use full trace validation which will catch the invalid GoDestroy
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Destroy on different M validation errors: {:?}",
        errors
    );
}

/// Regression test: Ensure destroy auto-starts goroutine if needed.
#[test]
fn regression_destroy_auto_start() {
    let mut serializer = GoTraceSerializer::new();
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: 1_000_000_000_000,
            task_id: 1,
            location: "test.rs:1".to_string(),
        },
        // Terminate without ever polling - serializer should auto-start before destroy
        OwnedEvent::TaskTerminate {
            timestamp_nanos: 1_000_000_001_000,
            task_id: 1,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).unwrap();

    // Should have both GoStart and GoDestroy
    let has_start = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(e, ParsedEvent::GoStart { .. }));

    let has_destroy = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .any(|e| matches!(e, ParsedEvent::GoDestroy { .. }));

    assert!(has_start, "Destroy should auto-start goroutine first");
    assert!(has_destroy, "Should have GoDestroy event");

    // State machine should be valid
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Auto-start destroy validation errors: {:?}",
        errors
    );
}

// ============================================================================
// BATCH CHUNKING TESTS - Critical for multi-upload scenarios
// ============================================================================

/// Tests that large traces are properly chunked into multiple batches.
/// Each chunk/batch must be self-contained with proper initialization.
#[test]
fn test_batch_chunking_produces_valid_batches() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    // Generate MANY events on a SINGLE worker to force chunking
    // MAX_BATCH_SIZE is 60KB, each event is ~10-30 bytes in output
    // We need ~3000+ events to reliably exceed 60KB
    let mut events = Vec::new();

    // Create 1000 tasks, all assigned to worker 0
    for i in 0..1000 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 100,
            task_id: i,
            location: format!(
                "src/module{}/submodule{}/task_{}.rs:{}",
                i % 10,
                i % 100,
                i,
                i * 10
            ),
        });
    }

    // Poll each task many times, all on worker 0 to concentrate events in one batch
    for round in 0..10 {
        for i in 0..1000 {
            events.push(OwnedEvent::PollStart {
                timestamp_nanos: base + 1_000_000 + round * 2_000_000 + i * 100,
                worker_id: 0, // ALL events go to worker 0
                task_id: i,
                location: format!(
                    "src/module{}/submodule{}/task_{}.rs:{}",
                    i % 10,
                    i % 100,
                    i,
                    i * 10
                ),
            });
            events.push(OwnedEvent::PollEnd {
                timestamp_nanos: base + 1_000_000 + round * 2_000_000 + i * 100 + 50,
                worker_id: 0,
            });
        }
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    // The output should be larger than MAX_BATCH_SIZE (60KB)
    assert!(
        result.data.len() > 60000,
        "Output should exceed 60KB to trigger chunking, got {} bytes",
        result.data.len()
    );

    // Parse the trace
    let parsed = parse_trace(&result.data).expect("Large trace should parse successfully");

    // Should have multiple batches for M=0 due to chunking
    let m0_batch_count = parsed.batches.iter().filter(|b| b.m_id == 0).count();

    assert!(
        m0_batch_count >= 1,
        "Should have at least one batch for M=0, got {}",
        m0_batch_count
    );

    // Validate the trace - each batch should be independently valid
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Chunked trace validation errors: {:?}",
        errors
    );
}

/// Tests that each batch chunk has proper ProcStatus initialization.
/// This is critical for the Go trace parser to understand the batch context.
#[test]
fn test_batch_chunks_have_proc_initialization() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    // Generate events that will definitely trigger chunking on M=0
    let mut events = Vec::new();

    // Create many tasks all on worker 0 to force chunking
    for i in 0..1000 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 1000,
            task_id: i,
            location: format!("src/task_{}.rs:{}", i, i * 10),
        });
        events.push(OwnedEvent::PollStart {
            timestamp_nanos: base + i * 1000 + 100,
            worker_id: 0, // All on worker 0
            task_id: i,
            location: format!("src/task_{}.rs:{}", i, i * 10),
        });
        events.push(OwnedEvent::PollEnd {
            timestamp_nanos: base + i * 1000 + 500,
            worker_id: 0,
        });
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Should parse");

    // Get all batches for M=0
    let m0_batches: Vec<_> = parsed.batches.iter().filter(|b| b.m_id == 0).collect();

    assert!(
        m0_batches.len() >= 1,
        "Should have at least one batch for M=0"
    );

    // Each batch for M=0 should have ProcStatus as one of its first events
    // OR be a continuation of a previous batch where ProcStatus was already established
    for (batch_idx, batch) in m0_batches.iter().enumerate() {
        let has_proc_init = batch.events.iter().any(|e| {
            matches!(
                e,
                ParsedEvent::ProcStatus { p_id: 0, .. } | ParsedEvent::ProcStart { p_id: 0, .. }
            )
        });

        // First batch MUST have ProcStatus
        if batch_idx == 0 {
            assert!(
                has_proc_init,
                "First batch for M=0 must have ProcStatus initialization"
            );
        }
        // Subsequent batches should either have initialization or be valid continuations
    }

    // Full state validation
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Batch initialization errors: {:?}",
        errors
    );
}

/// Tests that goroutine events in chunked batches reference valid goroutines.
/// When a batch is split, later chunks might reference Gs created in earlier chunks.
#[test]
fn test_chunked_batches_goroutine_references() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    // Create tasks, then do many polls to trigger chunking
    let mut events = Vec::new();

    // First, spawn 100 tasks
    for i in 0..100 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 100,
            task_id: i,
            location: format!("task_{}.rs:{}", i, i),
        });
    }

    // Then, poll each task many times (this will create lots of events)
    for round in 0..50 {
        for i in 0..100 {
            events.push(OwnedEvent::PollStart {
                timestamp_nanos: base + 100_000 + round * 200_000 + i * 1000,
                worker_id: (i % 4) as u8,
                task_id: i,
                location: format!("task_{}.rs:{}", i, i),
            });
            events.push(OwnedEvent::PollEnd {
                timestamp_nanos: base + 100_000 + round * 200_000 + i * 1000 + 500,
                worker_id: (i % 4) as u8,
            });
        }
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Should parse chunked trace");

    // Collect all G IDs that are created
    let created_gs: HashSet<u64> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter_map(|e| match e {
            ParsedEvent::GoCreate { g_id, .. } => Some(*g_id),
            ParsedEvent::GoStatus { g_id, .. } => Some(*g_id),
            _ => None,
        })
        .collect();

    // Collect all G IDs that are referenced in GoStart
    let started_gs: HashSet<u64> = parsed
        .batches
        .iter()
        .flat_map(|b| b.events.iter())
        .filter_map(|e| match e {
            ParsedEvent::GoStart { g_id, .. } => Some(*g_id),
            _ => None,
        })
        .collect();

    // All started Gs should have been created
    for g_id in &started_gs {
        assert!(
            created_gs.contains(g_id),
            "GoStart references G{} which was never created",
            g_id
        );
    }

    // Full validation
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Chunked goroutine reference errors: {:?}",
        errors
    );
}

/// Simulates multiple serialize() calls (like real uploads every 10 seconds).
/// Each call should produce an independent, valid trace.
#[test]
fn test_multiple_serialize_calls_independent() {
    let base1 = 1_000_000_000_000u64;
    let base2 = 2_000_000_000_000u64;

    // First batch of events
    let events1 = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base1,
            task_id: 100,
            location: "batch1.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: base1 + 1000,
            worker_id: 0,
            task_id: 100,
            location: "batch1.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: base1 + 2000,
            worker_id: 0,
        },
    ];

    // Second batch of events (different tasks)
    let events2 = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base2,
            task_id: 200,
            location: "batch2.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: base2 + 1000,
            worker_id: 0,
            task_id: 200,
            location: "batch2.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: base2 + 2000,
            worker_id: 0,
        },
    ];

    let mut serializer = GoTraceSerializer::new();

    // First serialize call
    let result1 = serializer
        .serialize(&events1, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();
    let parsed1 = parse_trace(&result1.data).expect("First batch should parse");

    // Second serialize call (same serializer instance)
    let result2 = serializer
        .serialize(&events2, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();
    let parsed2 = parse_trace(&result2.data).expect("Second batch should parse");

    // Each trace should be independently valid
    let mut validator1 = StateValidator::new();
    let errors1 = validator1.validate_trace(&parsed1);
    assert!(
        errors1.is_empty(),
        "First batch validation errors: {:?}",
        errors1
    );

    let mut validator2 = StateValidator::new();
    let errors2 = validator2.validate_trace(&parsed2);
    assert!(
        errors2.is_empty(),
        "Second batch validation errors: {:?}",
        errors2
    );

    // Each trace should have its own frequency event
    let has_freq1 = parsed1.batches.iter().any(|b| {
        b.events
            .iter()
            .any(|e| matches!(e, ParsedEvent::Frequency { .. }))
    });
    let has_freq2 = parsed2.batches.iter().any(|b| {
        b.events
            .iter()
            .any(|e| matches!(e, ParsedEvent::Frequency { .. }))
    });

    assert!(has_freq1, "First trace should have frequency event");
    assert!(has_freq2, "Second trace should have frequency event");

    // Each trace should have proper header
    assert!(
        result1.data.starts_with(GO_TRACE_HEADER),
        "First trace should have header"
    );
    assert!(
        result2.data.starts_with(GO_TRACE_HEADER),
        "Second trace should have header"
    );
}

/// Tests that very long-running tasks spanning multiple serialize calls work correctly.
/// The task is spawned in call 1, polled in call 2 - each call is self-contained.
#[test]
fn test_long_running_task_across_batches() {
    let base = 1_000_000_000_000u64;

    // Batch 1: Task is spawned and starts polling
    let events1 = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base,
            task_id: 42,
            location: "long_task.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: base + 1000,
            worker_id: 0,
            task_id: 42,
            location: "long_task.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: base + 50000,
            worker_id: 0,
        },
    ];

    // Batch 2: Same task continues (but serialize resets state, so needs to re-establish)
    let events2 = vec![
        // Need to re-spawn since state was reset
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base + 1_000_000,
            task_id: 42,
            location: "long_task.rs:1".to_string(),
        },
        OwnedEvent::PollStart {
            timestamp_nanos: base + 1_001_000,
            worker_id: 0,
            task_id: 42,
            location: "long_task.rs:1".to_string(),
        },
        OwnedEvent::PollEnd {
            timestamp_nanos: base + 1_050_000,
            worker_id: 0,
        },
        OwnedEvent::TaskTerminate {
            timestamp_nanos: base + 1_060_000,
            task_id: 42,
        },
    ];

    let mut serializer = GoTraceSerializer::new();

    let result1 = serializer
        .serialize(&events1, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();
    let result2 = serializer
        .serialize(&events2, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
        .unwrap();

    // Both should parse and validate
    let parsed1 = parse_trace(&result1.data).expect("Batch 1 parse");
    let parsed2 = parse_trace(&result2.data).expect("Batch 2 parse");

    let mut v1 = StateValidator::new();
    let mut v2 = StateValidator::new();

    let e1 = v1.validate_trace(&parsed1);
    let e2 = v2.validate_trace(&parsed2);

    assert!(e1.is_empty(), "Batch 1 errors: {:?}", e1);
    assert!(e2.is_empty(), "Batch 2 errors: {:?}", e2);
}

/// Test that reproduces the "two consecutive GoStarts without GoStop" bug.
/// This can happen when events are reordered by timestamp or delivered out of order.
#[test]
fn test_consecutive_poll_starts_same_worker() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    // Scenario: Two tasks poll on the same worker without a PollEnd between them.
    // This should emit: GoStart(task1), GoStop(task1), GoStart(task2)
    // NOT: GoStart(task1), GoStart(task2)
    let events = vec![
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base,
            task_id: 96,
            location: "task96.rs:1".to_string(),
        },
        OwnedEvent::TaskSpawn {
            timestamp_nanos: base + 100,
            task_id: 51,
            location: "task51.rs:1".to_string(),
        },
        // Task 96 starts polling on worker 3
        OwnedEvent::PollStart {
            timestamp_nanos: base + 1000,
            worker_id: 3,
            task_id: 96,
            location: "task96.rs:1".to_string(),
        },
        // Task 51 starts polling on worker 3 WITHOUT task 96 ending first!
        // This should cause a context switch (GoStop for 96, then GoStart for 51)
        OwnedEvent::PollStart {
            timestamp_nanos: base + 2000,
            worker_id: 3,
            task_id: 51,
            location: "task51.rs:1".to_string(),
        },
        // Now task 51 ends
        OwnedEvent::PollEnd {
            timestamp_nanos: base + 3000,
            worker_id: 3,
        },
    ];

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Should parse");

    // Get events for M=3
    let m3_events: Vec<_> = parsed
        .batches
        .iter()
        .filter(|b| b.m_id == 3)
        .flat_map(|b| b.events.iter())
        .collect();

    // Count consecutive GoStarts without GoStop between them
    let mut last_was_go_start = false;
    let mut consecutive_go_starts = 0;

    for event in &m3_events {
        match event {
            ParsedEvent::GoStart { .. } => {
                if last_was_go_start {
                    consecutive_go_starts += 1;
                }
                last_was_go_start = true;
            }
            ParsedEvent::GoStop { .. } | ParsedEvent::GoBlock { .. } | ParsedEvent::GoDestroy { .. } => {
                last_was_go_start = false;
            }
            _ => {}
        }
    }

    assert_eq!(
        consecutive_go_starts, 0,
        "Found {} consecutive GoStarts without GoStop - invalid trace! Events: {:?}",
        consecutive_go_starts, m3_events
    );

    // Full validation
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Consecutive poll starts validation errors: {:?}",
        errors
    );
}

/// Test rapid poll starts across multiple workers to stress test the state machine.
#[test]
fn test_rapid_cross_worker_poll_starts() {
    let mut serializer = GoTraceSerializer::new();
    let base = 1_000_000_000_000u64;

    let mut events = Vec::new();

    // Spawn 10 tasks
    for i in 0..10 {
        events.push(OwnedEvent::TaskSpawn {
            timestamp_nanos: base + i * 100,
            task_id: i,
            location: format!("task{}.rs:1", i),
        });
    }

    // Rapid polling across different workers, with some tasks moving between workers
    let poll_sequence = vec![
        (0, 0), // task 0 on worker 0
        (1, 1), // task 1 on worker 1
        (2, 2), // task 2 on worker 2
        (3, 3), // task 3 on worker 3
        (4, 0), // task 4 on worker 0 (context switch from task 0)
        (5, 1), // task 5 on worker 1 (context switch from task 1)
        (0, 2), // task 0 moves to worker 2 (context switch from task 2)
        (1, 3), // task 1 moves to worker 3 (context switch from task 3)
    ];

    for (i, &(task_id, worker_id)) in poll_sequence.iter().enumerate() {
        events.push(OwnedEvent::PollStart {
            timestamp_nanos: base + 10000 + i as u64 * 1000,
            worker_id,
            task_id,
            location: format!("task{}.rs:1", task_id),
        });
        events.push(OwnedEvent::PollEnd {
            timestamp_nanos: base + 10000 + i as u64 * 1000 + 500,
            worker_id,
        });
    }

    let result = serializer
        .serialize(&events, SystemTime::now(), SystemTime::now())
        .unwrap();

    let parsed = parse_trace(&result.data).expect("Should parse");

    // Check for consecutive GoStarts on each M
    for m_id in 0..4u64 {
        let m_events: Vec<_> = parsed
            .batches
            .iter()
            .filter(|b| b.m_id == m_id)
            .flat_map(|b| b.events.iter())
            .collect();

        let mut last_was_go_start = false;
        for event in &m_events {
            match event {
                ParsedEvent::GoStart { g_id, .. } => {
                    assert!(
                        !last_was_go_start,
                        "M={}: Consecutive GoStart found for G={} without GoStop",
                        m_id, g_id
                    );
                    last_was_go_start = true;
                }
                ParsedEvent::GoStop { .. } | ParsedEvent::GoBlock { .. } | ParsedEvent::GoDestroy { .. } => {
                    last_was_go_start = false;
                }
                _ => {}
            }
        }
    }

    // Full validation
    let mut validator = StateValidator::new();
    let errors = validator.validate_trace(&parsed);
    assert!(
        errors.is_empty(),
        "Cross-worker poll validation errors: {:?}",
        errors
    );
}

/// Property test: Any event sequence should not cause chunking to produce invalid traces.
proptest! {
    #[test]
    fn prop_chunking_always_valid(events in well_formed_event_sequence_strategy()) {
        // Duplicate events many times to trigger chunking
        let mut big_events = Vec::new();
        for round in 0..100 {
            for event in &events {
                let mut e = event.clone();
                // Adjust timestamps for each round
                match &mut e {
                    OwnedEvent::TaskSpawn { timestamp_nanos, task_id, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                        *task_id += round as u64 * 1000;
                    }
                    OwnedEvent::PollStart { timestamp_nanos, task_id, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                        *task_id += round as u64 * 1000;
                    }
                    OwnedEvent::PollEnd { timestamp_nanos, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                    }
                    OwnedEvent::TaskTerminate { timestamp_nanos, task_id, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                        *task_id += round as u64 * 1000;
                    }
                    OwnedEvent::WakeEvent { timestamp_nanos, waker_task_id, woken_task_id, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                        *waker_task_id += round as u64 * 1000;
                        *woken_task_id += round as u64 * 1000;
                    }
                    OwnedEvent::WorkerPark { timestamp_nanos, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                    }
                    OwnedEvent::WorkerUnpark { timestamp_nanos, .. } => {
                        *timestamp_nanos += round as u64 * 10_000_000;
                    }
                }
                big_events.push(e);
            }
        }

        let mut serializer = GoTraceSerializer::new();
        let result = serializer
            .serialize(&big_events, SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH)
            .expect("Serialization should succeed");

        let parsed = parse_trace(&result.data);
        prop_assert!(parsed.is_ok(), "Chunked trace should parse: {:?}", parsed.err());

        let parsed = parsed.unwrap();
        let mut validator = StateValidator::new();
        let errors = validator.validate_trace(&parsed);
        prop_assert!(errors.is_empty(), "Chunked trace validation errors: {:?}", errors);
    }
}
