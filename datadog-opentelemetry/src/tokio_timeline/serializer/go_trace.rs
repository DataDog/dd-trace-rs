// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

//! Go v2 execution trace format serializer.
//!
//! This module produces binary data compatible with Go's runtime/trace format (version 2),
//! which can be visualized in Go's trace viewer or compatible tools.
//!
//! ## Go Trace State Machine
//!
//! Go's trace format requires proper state transitions for goroutines and processors.
//! This encoder implements a state machine that tracks:
//!
//! - **Goroutine states**: `Runnable` (can start), `Running` (executing), `Waiting` (blocked)
//! - **Processor states**: `Running` (bound to M), `Idle` (not running)
//! - **M (thread) bindings**: Which G and P are currently executing on each M
//!
//! ### State Transitions
//!
//! - `GoCreate`: Creates G in `Runnable` state (requires M+P, no G bound)
//! - `GoStart`: `Runnable` -> `Running`, binds G to M (requires M+P, no G bound)
//! - `GoBlock`: `Running` -> `Waiting`, unbinds G (requires M+P+G)
//! - `GoUnblock`: `Waiting` -> `Runnable` (can happen from any context)
//! - `GoStop`: `Running` -> `Runnable`, unbinds G (requires M+P+G)
//! - `GoDestroy`: Deletes G (requires M+P+G running)
//!
//! ### Tokio Event Mapping
//!
//! - `TaskSpawn` -> `GoCreate` (creates goroutine)
//! - `PollStart` -> `GoStart` (goroutine starts running)
//! - `PollEnd` -> `GoStop` (goroutine yields voluntarily, stays runnable)
//! - `WakeEvent` -> `GoUnblock` (wakes waiting goroutine)
//! - `TaskTerminate` -> `GoDestroy` (goroutine exits)

use std::collections::HashMap;
use std::time::SystemTime;

use super::{SerializeError, SerializedTimeline, TimelineSerializer};
use crate::tokio_timeline::buffer::OwnedEvent;

/// Go trace header for version 1.23 format.
pub const GO_TRACE_HEADER: &[u8; 16] = b"go 1.23 trace\x00\x00\x00";

/// Go trace event types (v2 format for Go 1.22+).
/// From go/src/internal/trace/event/go122/event.go
#[allow(dead_code)]
mod event_type {
    // Structural events (iota starts at 0, EvNone=0 is unused)
    /// Event batch header [gen, m, time, size].
    pub const EV_EVENT_BATCH: u8 = 1;
    /// Stack table batch.
    pub const EV_STACKS: u8 = 2;
    /// Individual stack entry [id, frame_count, ...{pc, func_id, file_id, line}].
    pub const EV_STACK: u8 = 3;
    /// String table batch.
    pub const EV_STRINGS: u8 = 4;
    /// Individual string entry [id, len, data].
    pub const EV_STRING: u8 = 5;
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
    /// Goroutine blocks [timestamp, reason, stack ID].
    pub const EV_GO_BLOCK: u8 = 20;
    /// Goroutine is unblocked [timestamp, goroutine ID, goroutine seq, stack ID].
    pub const EV_GO_UNBLOCK: u8 = 21;
    // EvGoSyscallBegin = 22
    // EvGoSyscallEnd = 23
    // EvGoSyscallEndBlocked = 24
    /// Goroutine status at generation start [timestamp, goroutine ID, thread ID, status].
    pub const EV_GO_STATUS: u8 = 25;
}

/// Goroutine status values (from go/src/internal/trace/event/go122/event.go).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum GoStatus {
    /// Invalid/uninitialized state.
    Bad = 0,
    /// Goroutine is runnable (can be started).
    Runnable = 1,
    /// Goroutine is currently running.
    Running = 2,
    /// Goroutine is in a syscall (not used for Tokio mapping).
    Syscall = 3,
    /// Goroutine is waiting/blocked.
    Waiting = 4,
}

/// Processor status values (from go/src/internal/trace/event/go122/event.go).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ProcStatus {
    /// Invalid/uninitialized state.
    Bad = 0,
    /// Processor is running.
    Running = 1,
    /// Processor is idle.
    Idle = 2,
    /// Processor is in syscall (not used for Tokio mapping).
    Syscall = 3,
}

/// State of a goroutine in the trace state machine.
#[derive(Debug, Clone)]
struct GoroutineState {
    /// Current status of the goroutine.
    status: GoStatus,
    /// Sequence counter for ordering events.
    seq: u64,
}

impl GoroutineState {
    fn new() -> Self {
        Self {
            status: GoStatus::Runnable,
            seq: 0,
        }
    }

    /// Returns the next sequence number and increments the counter.
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

/// State of a processor in the trace state machine.
#[derive(Debug, Clone)]
struct ProcState {
    /// Current status of the processor.
    status: ProcStatus,
    /// Sequence counter for ordering events.
    seq: u64,
}

impl ProcState {
    fn new_idle() -> Self {
        Self {
            status: ProcStatus::Idle,
            seq: 0,
        }
    }

    /// Returns the next sequence number and increments the counter.
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
}

/// State of an M (OS thread) in the trace state machine.
#[derive(Debug, Clone, Default)]
struct MState {
    /// Currently bound goroutine (None if no G is running).
    g: Option<u64>,
    /// Currently bound processor (None if no P is bound).
    p: Option<u64>,
}

/// A single frame in a stack trace.
#[derive(Debug, Clone)]
struct StackFrame {
    /// Program counter (fake but unique).
    pc: u64,
    /// Function name string ID.
    func_id: u64,
    /// File path string ID.
    file_id: u64,
    /// Line number.
    line: u64,
}

/// Pre-defined reason strings for GoBlock/GoStop events.
/// These match common Go runtime block/stop reasons.
#[allow(dead_code)]
mod block_reason {
    pub const WAIT: &str = "wait";
    pub const SLEEP: &str = "sleep";
    pub const CHAN_RECV: &str = "chan receive";
    pub const SELECT: &str = "select";
    pub const IO_WAIT: &str = "IO wait";
    pub const YIELD: &str = "preempted"; // GoStop reason for voluntary yield
}

/// Go trace state machine that validates and emits proper event sequences.
///
/// This state machine tracks goroutine, processor, and thread states to ensure
/// that emitted events conform to Go's trace format requirements.
///
/// # M/P Mapping Strategy
///
/// Uses 1:1 identity mapping: `worker_id` maps to both M (OS thread) and P (processor)
/// with the same ID. For example, Tokio worker 0 → M=0, P=0.
///
/// This simplification works because Tokio's thread pool model aligns well with
/// Go's M:P binding, where each worker thread acts as both the OS thread and
/// the logical processor.
#[derive(Debug, Default)]
struct TraceStateMachine {
    /// Goroutine states indexed by goroutine ID.
    g_states: HashMap<u64, GoroutineState>,
    /// Processor states indexed by processor ID.
    p_states: HashMap<u64, ProcState>,
    /// M (thread) states indexed by M ID.
    m_states: HashMap<u64, MState>,
}

impl TraceStateMachine {
    fn new() -> Self {
        Self {
            g_states: HashMap::new(),
            p_states: HashMap::new(),
            m_states: HashMap::new(),
        }
    }

    /// Ensures a processor exists and is in running state, binding it to the M.
    /// Uses 1:1 mapping: worker_id maps to both M and P with the same ID.
    fn ensure_proc_running(&mut self, m_id: u64, output: &mut Vec<u8>, dt: u64) {
        let p_id = m_id; // 1:1 mapping

        // Check if M already has this P bound and running
        {
            let m_state = self.m_states.entry(m_id).or_default();
            if m_state.p == Some(p_id) {
                if let Some(p_state) = self.p_states.get(&p_id) {
                    if p_state.status == ProcStatus::Running {
                        return;
                    }
                }
            }

            // If this M has a different P, stop it first
            if let Some(old_p) = m_state.p {
                if old_p != p_id {
                    output.push(event_type::EV_PROC_STOP);
                    write_varint(output, dt);

                    if let Some(p_state) = self.p_states.get_mut(&old_p) {
                        p_state.status = ProcStatus::Idle;
                    }
                }
            }
        }

        let p_state = self
            .p_states
            .entry(p_id)
            .or_insert_with(ProcState::new_idle);

        if p_state.status != ProcStatus::Running {
            let p_seq = p_state.next_seq();
            output.push(event_type::EV_PROC_START);
            write_varint(output, dt);
            write_varint(output, p_id);
            write_varint(output, p_seq);
            p_state.status = ProcStatus::Running;
        }

        let m_state = self.m_states.entry(m_id).or_default();
        m_state.p = Some(p_id);
    }

    /// Creates a goroutine (GoCreate event).
    /// Requires: M+P bound. Does nothing if G already exists.
    fn go_create(
        &mut self,
        m_id: u64,
        g_id: u64,
        output: &mut Vec<u8>,
        dt: u64,
        new_stack: u64,
        stack: u64,
    ) {
        self.ensure_proc_running(m_id, output, dt);

        // Don't recreate if already exists
        if self.g_states.contains_key(&g_id) {
            return;
        }

        self.g_states.insert(g_id, GoroutineState::new());

        // GoCreate: dt, new_g, new_stack, stack
        output.push(event_type::EV_GO_CREATE);
        write_varint(output, dt);
        write_varint(output, g_id);
        write_varint(output, new_stack); // stack where new goroutine will start
        write_varint(output, stack); // stack of the creator
    }

    /// Starts a goroutine (GoStart event).
    /// Handles edge cases: auto-creates unknown G, blocks running G, unblocks waiting G.
    #[allow(clippy::too_many_arguments)]
    fn go_start(
        &mut self,
        m_id: u64,
        g_id: u64,
        output: &mut Vec<u8>,
        dt: u64,
        block_stack: u64,
        wake_stack: u64,
        create_stack: u64,
    ) {
        self.ensure_proc_running(m_id, output, dt);

        // Check if there's a different G running on this M that we need to block first
        let running_g_to_block = {
            let m_state = self.m_states.entry(m_id).or_default();
            match m_state.g {
                Some(running_g) if running_g == g_id => {
                    // Already running this G, nothing to do
                    return;
                }
                Some(running_g) => {
                    m_state.g = None;
                    Some(running_g)
                }
                None => None,
            }
        };

        // Stop the currently running G if needed (context switch is voluntary yield, not block)
        if let Some(running_g) = running_g_to_block {
            self.go_stop_internal(running_g, output, dt, 0, block_stack); // reason=0 (preempted)
        }

        // Ensure the goroutine exists (auto-create if unknown)
        if !self.g_states.contains_key(&g_id) {
            self.go_create(m_id, g_id, output, dt, create_stack, create_stack);
        }

        let g_state = self.g_states.get_mut(&g_id).expect("just created");

        // If goroutine is Waiting, unblock it first
        if g_state.status == GoStatus::Waiting {
            let g_seq = g_state.next_seq();
            output.push(event_type::EV_GO_UNBLOCK);
            write_varint(output, dt);
            write_varint(output, g_id);
            write_varint(output, g_seq);
            write_varint(output, wake_stack);
            g_state.status = GoStatus::Runnable;
        }

        // Start the goroutine if runnable
        if g_state.status == GoStatus::Runnable {
            let g_seq = g_state.next_seq();
            output.push(event_type::EV_GO_START);
            write_varint(output, dt);
            write_varint(output, g_id);
            write_varint(output, g_seq);
            g_state.status = GoStatus::Running;

            let m_state = self.m_states.entry(m_id).or_default();
            m_state.g = Some(g_id);
        }
    }

    /// Internal helper to emit GoBlock for a goroutine.
    fn go_block_internal(
        &mut self,
        g_id: u64,
        output: &mut Vec<u8>,
        dt: u64,
        reason: u64,
        stack: u64,
    ) {
        let Some(g_state) = self.g_states.get_mut(&g_id) else {
            return;
        };
        if g_state.status != GoStatus::Running {
            return;
        }
        // GoBlock: dt, reason, stack
        output.push(event_type::EV_GO_BLOCK);
        write_varint(output, dt);
        write_varint(output, reason);
        write_varint(output, stack);
        g_state.status = GoStatus::Waiting;
    }

    /// Blocks the currently running goroutine on an M (GoBlock event).
    /// Use this for actual blocking operations (mutexes, channels, I/O).
    #[allow(dead_code)]
    fn go_block(&mut self, m_id: u64, output: &mut Vec<u8>, dt: u64, reason: u64, stack: u64) {
        let m_state = self.m_states.entry(m_id).or_default();
        let Some(g_id) = m_state.g.take() else {
            return;
        };
        self.go_block_internal(g_id, output, dt, reason, stack);
    }

    /// Internal helper to emit GoStop for a goroutine (voluntary yield, stays runnable).
    fn go_stop_internal(
        &mut self,
        g_id: u64,
        output: &mut Vec<u8>,
        dt: u64,
        reason: u64,
        stack: u64,
    ) {
        let Some(g_state) = self.g_states.get_mut(&g_id) else {
            return;
        };
        if g_state.status != GoStatus::Running {
            return;
        }
        // GoStop: dt, reason, stack
        // Unlike GoBlock, the goroutine stays Runnable (not Waiting)
        output.push(event_type::EV_GO_STOP);
        write_varint(output, dt);
        write_varint(output, reason);
        write_varint(output, stack);
        g_state.status = GoStatus::Runnable; // Key difference from GoBlock
    }

    /// Stops the currently running goroutine on an M (GoStop event).
    /// Use this for voluntary yields (e.g., Tokio poll returning Pending).
    /// Unlike go_block, the goroutine stays Runnable and can be started again
    /// without needing a GoUnblock event.
    fn go_stop(&mut self, m_id: u64, output: &mut Vec<u8>, dt: u64, reason: u64, stack: u64) {
        let m_state = self.m_states.entry(m_id).or_default();
        let Some(g_id) = m_state.g.take() else {
            return;
        };
        self.go_stop_internal(g_id, output, dt, reason, stack);
    }

    /// Unblocks a goroutine (GoUnblock event).
    /// No-op if G doesn't exist or is already Runnable.
    fn go_unblock(&mut self, g_id: u64, output: &mut Vec<u8>, dt: u64, stack: u64) {
        let Some(g_state) = self.g_states.get_mut(&g_id) else {
            return;
        };
        if g_state.status != GoStatus::Waiting {
            return;
        }
        let g_seq = g_state.next_seq();
        output.push(event_type::EV_GO_UNBLOCK);
        write_varint(output, dt);
        write_varint(output, g_id);
        write_varint(output, g_seq);
        write_varint(output, stack);
        g_state.status = GoStatus::Runnable;
    }

    /// Stops the processor on an M (ProcStop event).
    /// This represents a worker thread parking (going idle).
    fn proc_stop(&mut self, m_id: u64, output: &mut Vec<u8>, dt: u64) {
        let m_state = self.m_states.entry(m_id).or_default();
        let p_id = m_state.p.unwrap_or(m_id); // Use 1:1 mapping if not bound

        let Some(p_state) = self.p_states.get_mut(&p_id) else {
            return;
        };
        if p_state.status != ProcStatus::Running {
            return;
        }

        // ProcStop: dt
        output.push(event_type::EV_PROC_STOP);
        write_varint(output, dt);
        p_state.status = ProcStatus::Idle;
        m_state.p = None;
    }

    /// Starts the processor on an M (ProcStart event).
    /// This represents a worker thread unparking (becoming active).
    fn proc_start(&mut self, m_id: u64, output: &mut Vec<u8>, dt: u64) {
        let p_id = m_id; // 1:1 mapping

        let p_state = self
            .p_states
            .entry(p_id)
            .or_insert_with(ProcState::new_idle);

        if p_state.status == ProcStatus::Running {
            return; // Already running
        }

        let p_seq = p_state.next_seq();
        // ProcStart: dt, P ID, P seq
        output.push(event_type::EV_PROC_START);
        write_varint(output, dt);
        write_varint(output, p_id);
        write_varint(output, p_seq);
        p_state.status = ProcStatus::Running;

        let m_state = self.m_states.entry(m_id).or_default();
        m_state.p = Some(p_id);
    }

    /// Destroys a goroutine (GoDestroy event).
    /// Ensures G is running on this M first (starts it if needed).
    ///
    /// Note: If the G is running on a different M, we cannot destroy it from here
    /// because we can't emit the required GoStop on the other M's batch. In this case,
    /// we skip the destroy - the trace will show the goroutine as still running but
    /// this is better than emitting an invalid GoDestroy without a prior GoStart.
    #[allow(clippy::too_many_arguments)]
    fn go_destroy(
        &mut self,
        m_id: u64,
        g_id: u64,
        output: &mut Vec<u8>,
        dt: u64,
        block_stack: u64,
        wake_stack: u64,
        create_stack: u64,
    ) {
        // If G doesn't exist, nothing to destroy
        if !self.g_states.contains_key(&g_id) {
            return;
        }

        // Try to ensure G is running on this M
        {
            let m_state = self.m_states.entry(m_id).or_default();
            if m_state.g != Some(g_id) {
                self.go_start(
                    m_id,
                    g_id,
                    output,
                    dt,
                    block_stack,
                    wake_stack,
                    create_stack,
                );
            }
        }

        // Verify that go_start actually bound this G to this M.
        // If the G was already Running on a different M, go_start won't have
        // emitted a GoStart (because status == Running, not Runnable), and we
        // shouldn't emit GoDestroy without a preceding GoStart on this M.
        {
            let m_state = self.m_states.entry(m_id).or_default();
            if m_state.g != Some(g_id) {
                // G is not running on this M - cannot destroy it from here.
                // This can happen when a task terminates while it was last
                // polled on a different worker.
                return;
            }
        }

        // Now destroy it
        let Some(g_state) = self.g_states.get(&g_id) else {
            return;
        };
        if g_state.status != GoStatus::Running {
            return;
        }

        output.push(event_type::EV_GO_DESTROY);
        write_varint(output, dt);
        self.g_states.remove(&g_id);

        let m_state = self.m_states.entry(m_id).or_default();
        m_state.g = None;
    }
}

/// Serializer for Go v2 execution trace format.
///
/// Converts Tokio runtime events into a binary trace format compatible with
/// Go's `runtime/trace` (v2, Go 1.22+), enabling visualization in Datadog's
/// Timeline View or Go's native trace viewer.
///
/// # Event Mapping
///
/// - `TaskSpawn` → `GoCreate` (new goroutine in Runnable state)
/// - `PollStart` → `GoStart` (goroutine begins execution)
/// - `PollEnd` → `GoStop` (voluntary yield, stays Runnable)
/// - `WakeEvent` → `GoUnblock` (Waiting → Runnable)
/// - `TaskTerminate` → `GoDestroy` (goroutine exits)
/// - `WorkerPark` → `ProcStop` (worker thread idle)
/// - `WorkerUnpark` → `ProcStart` (worker thread active)
///
/// # Usage
///
/// ```ignore
/// let mut serializer = GoTraceSerializer::new();
/// let result = serializer.serialize(&events, batch_start, batch_end)?;
/// // result.data contains the binary Go trace
/// // result.filename is "go.trace"
/// ```
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
    /// Stack table: stack_id -> frames.
    stack_table: HashMap<u64, Vec<StackFrame>>,
    /// Next stack ID to assign.
    next_stack_id: u64,
    /// Next fake program counter.
    next_pc: u64,
    /// Pre-computed stack IDs for different event types.
    stack_ids: StackIds,
    /// Per-task stack IDs (task_id -> stack_id for that task's entry point).
    /// The bottom frame of each task's stack is its spawn location, which becomes
    /// the goroutine's display name in the timeline.
    task_stack_map: HashMap<u64, u64>,
}

/// Pre-computed stack IDs for different event types.
#[derive(Debug, Default)]
struct StackIds {
    /// Stack for task creation (GoCreate) - used as creator's stack.
    create_stack: u64,
    /// Stack for poll start (GoStart) - generic runtime stack.
    start_stack: u64,
    /// Stack for poll end / voluntary yield (GoStop).
    yield_stack: u64,
    /// Stack for blocking operations (GoBlock).
    block_stack: u64,
    /// Stack for wake (GoUnblock).
    wake_stack: u64,
    /// Stack for terminate (GoDestroy).
    destroy_stack: u64,
}

impl GoTraceSerializer {
    /// Creates a new Go trace serializer.
    pub fn new() -> Self {
        Self {
            string_table: HashMap::new(),
            next_string_id: 1, // 0 is reserved for empty string
            task_id_map: HashMap::new(),
            next_goroutine_id: 2, /* Start at 2 since G=1 is reserved for "main" goroutine via
                                   * GoStatus */
            stack_table: HashMap::new(),
            next_stack_id: 1, // 0 is reserved for "no stack"
            next_pc: 0x1000,  // Start fake PCs at reasonable address
            stack_ids: StackIds::default(),
            task_stack_map: HashMap::new(),
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

    /// Creates a stack frame with the given function, file, and line.
    fn create_frame(&mut self, func: &str, file: &str, line: u64) -> StackFrame {
        let pc = self.next_pc;
        self.next_pc += 0x10; // Each "function" gets 16 bytes of fake address space
        StackFrame {
            pc,
            func_id: self.get_or_create_string_id(func),
            file_id: self.get_or_create_string_id(file),
            line,
        }
    }

    /// Creates a new stack and returns its ID.
    fn create_stack(&mut self, frames: Vec<StackFrame>) -> u64 {
        let id = self.next_stack_id;
        self.next_stack_id += 1;
        self.stack_table.insert(id, frames);
        id
    }

    /// Creates a per-task stack using the spawn location as the entry point.
    /// The spawn location becomes the bottom frame, which determines the
    /// goroutine's display name in Datadog's timeline.
    fn create_task_stack(&mut self, task_id: u64, location: &str) -> u64 {
        // Check if we already have a stack for this task
        if let Some(&stack_id) = self.task_stack_map.get(&task_id) {
            return stack_id;
        }

        // Parse location like "src/main.rs:42" into file and line
        let (file, line, func_name) = parse_location(location);

        // Create a stack with the spawn location as the bottom frame
        // This makes the goroutine's name be the spawn location
        let frames = vec![
            // Top frame: tokio runtime (most recent call)
            self.create_frame(
                "tokio::runtime::task::harness::poll",
                "tokio/src/runtime/task/harness.rs",
                156,
            ),
            // Bottom frame: the spawn location (this becomes the goroutine name)
            self.create_frame(&func_name, &file, line),
        ];

        let stack_id = self.create_stack(frames);
        self.task_stack_map.insert(task_id, stack_id);
        stack_id
    }

    /// Gets the stack ID for a task, or returns the default start_stack if not found.
    fn get_task_stack(&self, task_id: u64) -> u64 {
        self.task_stack_map
            .get(&task_id)
            .copied()
            .unwrap_or(self.stack_ids.start_stack)
    }

    /// Initializes pre-defined stacks for Tokio events.
    /// These represent a plausible Tokio runtime call stack.
    fn init_stacks(&mut self) {
        // Create realistic-looking Tokio runtime stacks
        // Stack for task creation (spawning a new task)
        let create_frames = vec![
            self.create_frame("tokio::runtime::spawn", "tokio/src/runtime/spawn.rs", 42),
            self.create_frame("tokio::task::JoinHandle::new", "tokio/src/task/join.rs", 87),
            self.create_frame("main", "src/main.rs", 15),
        ];
        self.stack_ids.create_stack = self.create_stack(create_frames);

        // Stack for poll start (task begins executing)
        let start_frames = vec![
            self.create_frame(
                "tokio::runtime::task::harness::poll",
                "tokio/src/runtime/task/harness.rs",
                156,
            ),
            self.create_frame(
                "tokio::runtime::scheduler::multi_thread::worker::run",
                "tokio/src/runtime/scheduler/multi_thread/worker.rs",
                423,
            ),
        ];
        self.stack_ids.start_stack = self.create_stack(start_frames);

        // Stack for poll end / voluntary yield (task returns Pending)
        let yield_frames = vec![
            self.create_frame(
                "tokio::runtime::task::harness::poll",
                "tokio/src/runtime/task/harness.rs",
                167,
            ),
            self.create_frame(
                "tokio::runtime::scheduler::multi_thread::worker::run",
                "tokio/src/runtime/scheduler/multi_thread/worker.rs",
                445,
            ),
        ];
        self.stack_ids.yield_stack = self.create_stack(yield_frames);

        // Stack for blocking operations (task blocks on I/O, mutex, etc.)
        let block_frames = vec![
            self.create_frame(
                "tokio::sync::oneshot::Receiver::poll",
                "tokio/src/sync/oneshot.rs",
                312,
            ),
            self.create_frame(
                "tokio::runtime::task::harness::poll",
                "tokio/src/runtime/task/harness.rs",
                189,
            ),
        ];
        self.stack_ids.block_stack = self.create_stack(block_frames);

        // Stack for wake (task is woken)
        let wake_frames = vec![
            self.create_frame(
                "tokio::sync::oneshot::Sender::send",
                "tokio/src/sync/oneshot.rs",
                198,
            ),
            self.create_frame(
                "tokio::runtime::task::waker::wake",
                "tokio/src/runtime/task/waker.rs",
                67,
            ),
        ];
        self.stack_ids.wake_stack = self.create_stack(wake_frames);

        // Stack for task termination
        let destroy_frames = vec![
            self.create_frame(
                "tokio::runtime::task::harness::complete",
                "tokio/src/runtime/task/harness.rs",
                245,
            ),
            self.create_frame(
                "tokio::runtime::scheduler::multi_thread::worker::run",
                "tokio/src/runtime/scheduler/multi_thread/worker.rs",
                467,
            ),
        ];
        self.stack_ids.destroy_stack = self.create_stack(destroy_frames);
    }

    /// Writes the stack table inside an EventBatch (M=-1).
    fn write_stack_table(&self, output: &mut Vec<u8>, base_timestamp: u64) {
        if self.stack_table.is_empty() {
            return;
        }

        // Collect stacks sorted by ID
        let mut stacks: Vec<(&u64, &Vec<StackFrame>)> = self.stack_table.iter().collect();
        stacks.sort_by_key(|(id, _)| *id);

        // Build the batch data:
        // - EvStacks marker (no gen/size - just a marker)
        // - EvStack entries: type, id, frame_count, frames
        let mut batch_data = Vec::new();
        batch_data.push(event_type::EV_STACKS);
        for (id, frames) in stacks {
            batch_data.push(event_type::EV_STACK);
            write_varint(&mut batch_data, *id);
            write_varint(&mut batch_data, frames.len() as u64);
            for frame in frames {
                write_varint(&mut batch_data, frame.pc);
                write_varint(&mut batch_data, frame.func_id);
                write_varint(&mut batch_data, frame.file_id);
                write_varint(&mut batch_data, frame.line);
            }
        }

        // Wrap in EventBatch with M=-1
        output.push(event_type::EV_EVENT_BATCH);
        write_varint(output, 1); // generation = 1
        write_varint(output, u64::MAX); // M = -1
        write_varint(output, base_timestamp);
        write_varint(output, batch_data.len() as u64);
        output.extend_from_slice(&batch_data);
    }

    /// Writes the string table inside an EventBatch (M=-1).
    fn write_string_table(&self, output: &mut Vec<u8>, base_timestamp: u64) {
        if self.string_table.is_empty() {
            return;
        }

        // Collect strings sorted by ID
        let mut strings: Vec<(&String, &u64)> = self.string_table.iter().collect();
        strings.sort_by_key(|(_, id)| *id);

        // Build the batch data:
        // - EvStrings marker (no gen/size - just a marker)
        // - EvString entries: type, id, len, data
        let mut batch_data = Vec::new();
        batch_data.push(event_type::EV_STRINGS);
        for (s, id) in strings {
            batch_data.push(event_type::EV_STRING);
            write_varint(&mut batch_data, *id);
            write_varint(&mut batch_data, s.len() as u64);
            batch_data.extend_from_slice(s.as_bytes());
        }

        // Wrap in EventBatch with M=-1
        output.push(event_type::EV_EVENT_BATCH);
        write_varint(output, 1); // generation = 1
        write_varint(output, u64::MAX); // M = -1
        write_varint(output, base_timestamp);
        write_varint(output, batch_data.len() as u64);
        output.extend_from_slice(&batch_data);
    }

    /// Groups events by worker ID, sorted by timestamp within each group.
    #[cfg(test)]
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

/// Per-M (thread) batch state for multi-worker trace generation.
#[derive(Debug)]
struct MBatchState {
    /// Event data buffer for this M.
    data: Vec<u8>,
    /// Last timestamp for delta calculation.
    last_timestamp: u64,
    /// Base timestamp for the current batch.
    batch_base_timestamp: u64,
    /// Whether ProcStatus has been emitted for this M's P.
    proc_initialized: bool,
}

impl MBatchState {
    fn new(base_timestamp: u64) -> Self {
        Self {
            data: Vec::new(),
            last_timestamp: base_timestamp,
            batch_base_timestamp: base_timestamp,
            proc_initialized: false,
        }
    }
}

impl TimelineSerializer for GoTraceSerializer {
    fn serialize(
        &mut self,
        events: &[OwnedEvent],
        _batch_start: SystemTime,
        _batch_end: SystemTime,
    ) -> Result<SerializedTimeline, SerializeError> {
        // Reset state for each batch
        self.string_table.clear();
        self.next_string_id = 1;
        self.task_id_map.clear();
        self.next_goroutine_id = 2; // G=1 reserved for main goroutine
        self.stack_table.clear();
        self.next_stack_id = 1;
        self.next_pc = 0x1000;
        self.stack_ids = StackIds::default();
        self.task_stack_map.clear();

        // Initialize stacks and reason strings
        self.init_stacks();
        let _wait_reason_id = self.get_or_create_string_id(block_reason::WAIT);
        let yield_reason_id = self.get_or_create_string_id(block_reason::YIELD);

        let mut output = Vec::new();

        // Write header "go 1.22 trace"
        output.extend_from_slice(GO_TRACE_HEADER);

        // Use monotonic timestamps directly (like real Go traces).
        // Go trace uses ~15.6MHz frequency, so we divide nanoseconds by 64 to convert.
        const NS_TO_TICKS: u64 = 64; // 1GHz / 15.625MHz ≈ 64

        let min_event_timestamp = events
            .iter()
            .map(|e| e.timestamp_nanos())
            .min()
            .unwrap_or(0);

        // Use the monotonic timestamp directly (divided by 64 for tick conversion)
        // This gives timestamps similar to real Go traces (~47 days of ticks)
        let base_timestamp = min_event_timestamp / NS_TO_TICKS;

        // First pass: collect all task IDs, strings, and unique worker IDs
        let mut worker_ids = std::collections::BTreeSet::new();
        worker_ids.insert(0u8); // Always have M=0 for events without worker_id

        for event in events {
            match event {
                OwnedEvent::TaskSpawn {
                    task_id, location, ..
                } => {
                    self.map_task_id(*task_id);
                    self.get_or_create_string_id(location);
                    // Create a per-task stack with the spawn location as the entry point
                    // This gives each goroutine a unique name in the timeline
                    self.create_task_stack(*task_id, location);
                }
                OwnedEvent::PollStart {
                    task_id,
                    location,
                    worker_id,
                    ..
                } => {
                    self.map_task_id(*task_id);
                    self.get_or_create_string_id(location);
                    worker_ids.insert(*worker_id);
                }
                OwnedEvent::PollEnd { worker_id, .. } => {
                    worker_ids.insert(*worker_id);
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
                OwnedEvent::WorkerPark { worker_id, .. }
                | OwnedEvent::WorkerUnpark { worker_id, .. } => {
                    worker_ids.insert(*worker_id);
                }
            }
        }

        // === First batch: Frequency only (M=-1) ===
        let mut freq_data = Vec::new();
        freq_data.push(event_type::EV_FREQUENCY);
        write_varint(&mut freq_data, 15_625_000); // ~15.6MHz matches Go's trace frequency

        output.push(event_type::EV_EVENT_BATCH);
        write_varint(&mut output, 1); // generation = 1
        write_varint(&mut output, u64::MAX); // M = -1 (special batch)
        write_varint(&mut output, base_timestamp);
        write_varint(&mut output, freq_data.len() as u64);
        output.extend_from_slice(&freq_data);

        // === Write string table (must come before stacks since stacks reference strings) ===
        self.write_string_table(&mut output, base_timestamp);

        // === Write stack table ===
        self.write_stack_table(&mut output, base_timestamp);

        // Copy stack IDs for use in the loop (avoids borrow issues with self)
        let create_stack = self.stack_ids.create_stack;
        let _start_stack = self.stack_ids.start_stack;
        let yield_stack = self.stack_ids.yield_stack;
        let block_stack = self.stack_ids.block_stack;
        let wake_stack = self.stack_ids.wake_stack;
        // Note: destroy_stack exists but isn't used because GoDestroy event
        // in Go trace format doesn't include a stack argument (only dt)

        // === Process events through state machine, routing to per-M batches ===
        // Sort all events by timestamp for proper ordering
        let mut all_events: Vec<&OwnedEvent> = events.iter().collect();
        all_events.sort_by_key(|e| e.timestamp_nanos());

        // Initialize state machine and per-M batch buffers
        let mut state_machine = TraceStateMachine::new();
        let mut m_batches: HashMap<u64, MBatchState> = HashMap::new();

        // Initialize batch state for each worker
        for &worker_id in &worker_ids {
            m_batches.insert(worker_id as u64, MBatchState::new(base_timestamp));
        }

        // Maximum batch size to stay under Go's 65536 byte limit
        const MAX_BATCH_SIZE: usize = 60000;

        // Helper to flush an M's batch to output
        let flush_m_batch = |output: &mut Vec<u8>, m_id: u64, batch: &mut MBatchState| {
            if batch.data.is_empty() {
                return;
            }
            output.push(event_type::EV_EVENT_BATCH);
            write_varint(output, 1); // generation = 1
            write_varint(output, m_id);
            write_varint(output, batch.batch_base_timestamp);
            write_varint(output, batch.data.len() as u64);
            output.extend_from_slice(&batch.data);
            batch.data.clear();
            batch.batch_base_timestamp = batch.last_timestamp;
        };

        // Process each event through the state machine
        for event in &all_events {
            // Determine which M this event belongs to
            let m_id: u64 = match event {
                OwnedEvent::PollStart { worker_id, .. }
                | OwnedEvent::PollEnd { worker_id, .. }
                | OwnedEvent::WorkerPark { worker_id, .. }
                | OwnedEvent::WorkerUnpark { worker_id, .. } => *worker_id as u64,
                // Events without worker_id go to M=0
                OwnedEvent::TaskSpawn { .. }
                | OwnedEvent::TaskTerminate { .. }
                | OwnedEvent::WakeEvent { .. } => 0,
            };

            let batch = m_batches
                .entry(m_id)
                .or_insert_with(|| MBatchState::new(base_timestamp));

            // Check if we need to flush before adding more events
            if batch.data.len() > MAX_BATCH_SIZE {
                flush_m_batch(&mut output, m_id, batch);
            }

            // Emit ProcStatus for this M's P if not yet done
            // Use Running status (like real Go traces) so we don't need ProcStart
            if !batch.proc_initialized {
                // ProcStatus: P is running
                batch.data.push(event_type::EV_PROC_STATUS);
                write_varint(&mut batch.data, 0); // dt = 0
                write_varint(&mut batch.data, m_id); // P = m_id (1:1 mapping)
                write_varint(&mut batch.data, ProcStatus::Running as u64);

                // GoStatus: Establish a "main" goroutine (G=1) as Running on this M
                // This matches how real Go traces work - G1 exists from trace start
                if m_id == 0 {
                    batch.data.push(event_type::EV_GO_STATUS);
                    write_varint(&mut batch.data, 1); // dt = 1
                    write_varint(&mut batch.data, 1); // g = 1 (main goroutine)
                    write_varint(&mut batch.data, m_id); // m = this thread
                    write_varint(&mut batch.data, GoStatus::Running as u64);

                    // Tell state machine G1 exists and is running
                    let g_state = state_machine
                        .g_states
                        .entry(1)
                        .or_insert_with(GoroutineState::new);
                    g_state.status = GoStatus::Running;
                    state_machine.m_states.entry(m_id).or_default().g = Some(1);
                }

                batch.proc_initialized = true;

                // Tell state machine this P is already running
                state_machine.p_states.entry(m_id).or_insert_with(|| {
                    let mut p = ProcState::new_idle();
                    p.status = ProcStatus::Running;
                    p
                });
                // Bind P to M
                state_machine.m_states.entry(m_id).or_default().p = Some(m_id);
            }

            // Convert monotonic timestamp to ticks
            let event_monotonic = event.timestamp_nanos();
            let timestamp = event_monotonic / NS_TO_TICKS;
            let dt = timestamp.saturating_sub(batch.last_timestamp);
            batch.last_timestamp = timestamp;

            match event {
                OwnedEvent::TaskSpawn { task_id, .. } => {
                    let g_id = self.task_id_map.get(task_id).copied().unwrap_or(1);
                    // Use the per-task stack (based on spawn location) as the new goroutine's entry
                    // point This gives each goroutine a unique name in the
                    // timeline
                    let task_stack = self.get_task_stack(*task_id);
                    state_machine.go_create(
                        m_id,
                        g_id,
                        &mut batch.data,
                        dt,
                        task_stack, // new_stack: where the goroutine starts (determines its name)
                        create_stack, // stack: the creator's stack
                    );
                }
                OwnedEvent::PollStart { task_id, .. } => {
                    let g_id = self.task_id_map.get(task_id).copied().unwrap_or(1);
                    state_machine.go_start(
                        m_id,
                        g_id,
                        &mut batch.data,
                        dt,
                        block_stack,
                        wake_stack,
                        create_stack,
                    );
                }
                OwnedEvent::PollEnd { .. } => {
                    // GoStop: voluntary yield, goroutine stays runnable
                    // (Unlike GoBlock which would make it Waiting)
                    state_machine.go_stop(m_id, &mut batch.data, dt, yield_reason_id, yield_stack);
                }
                OwnedEvent::WakeEvent { woken_task_id, .. } => {
                    let g_id = self.task_id_map.get(woken_task_id).copied().unwrap_or(1);
                    state_machine.go_unblock(g_id, &mut batch.data, dt, wake_stack);
                }
                OwnedEvent::TaskTerminate { task_id, .. } => {
                    let g_id = self.task_id_map.get(task_id).copied().unwrap_or(1);
                    state_machine.go_destroy(
                        m_id,
                        g_id,
                        &mut batch.data,
                        dt,
                        block_stack,
                        wake_stack,
                        create_stack,
                    );
                }
                OwnedEvent::WorkerPark { .. } => {
                    // Worker thread is parking (going idle)
                    // Stop the processor to show it's idle
                    state_machine.proc_stop(m_id, &mut batch.data, dt);
                }
                OwnedEvent::WorkerUnpark { .. } => {
                    // Worker thread is unparking (becoming active)
                    // Start the processor to show it's active
                    state_machine.proc_start(m_id, &mut batch.data, dt);
                }
            }
        }

        // Flush all remaining M batches
        // Sort by M ID for deterministic output
        let mut m_ids: Vec<u64> = m_batches.keys().copied().collect();
        m_ids.sort();
        for m_id in m_ids {
            if let Some(batch) = m_batches.get_mut(&m_id) {
                flush_m_batch(&mut output, m_id, batch);
            }
        }

        Ok(SerializedTimeline {
            data: output,
            name: "execution-trace",
            filename: "go.trace",
            content_type: "application/octet-stream",
        })
    }
}

/// Parses a location string like "src/main.rs:42" into (file, line, func_name).
/// The func_name is derived from the file path to create a meaningful goroutine name.
fn parse_location(location: &str) -> (String, u64, String) {
    // Split on ':' to get file and line
    let (file, line) = if let Some(colon_pos) = location.rfind(':') {
        let file = &location[..colon_pos];
        let line_str = &location[colon_pos + 1..];
        let line = line_str.parse().unwrap_or(1);
        (file.to_string(), line)
    } else {
        (location.to_string(), 1)
    };

    // Create a function name from the location
    // e.g., "src/main.rs:42" -> "main.rs:42" (use basename + line as the name)
    let func_name = if let Some(slash_pos) = location.rfind('/') {
        location[slash_pos + 1..].to_string()
    } else {
        location.to_string()
    };

    (file, line, func_name)
}

/// Writes a variable-length integer (LEB128 unsigned) to the output.
pub(crate) fn write_varint(output: &mut Vec<u8>, mut value: u64) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a variable-length integer (LEB128 unsigned) from input.
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

    #[test]
    fn test_state_machine_basic_flow() {
        // Test: spawn → start → end → wake → start → terminate
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();

        // Use dummy stack IDs for testing (0 = no stack)
        let stack = 1u64;

        // TaskSpawn → GoCreate
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        assert!(state_machine.g_states.contains_key(&1));
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);

        // PollStart → GoStart
        state_machine.go_start(0, 1, &mut output, 100, stack, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Running);
        assert_eq!(state_machine.m_states[&0].g, Some(1));

        // PollEnd → GoStop (voluntary yield, stays runnable)
        state_machine.go_stop(0, &mut output, 200, 0, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);
        assert_eq!(state_machine.m_states[&0].g, None);

        // WakeEvent → GoUnblock (no-op since goroutine is already Runnable from GoStop)
        state_machine.go_unblock(1, &mut output, 300, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);

        // PollStart → GoStart (can start directly since already Runnable from GoStop)
        state_machine.go_start(0, 1, &mut output, 400, stack, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Running);

        // TaskTerminate → GoDestroy
        state_machine.go_destroy(0, 1, &mut output, 500, stack, stack, stack);
        assert!(!state_machine.g_states.contains_key(&1));
        assert_eq!(state_machine.m_states[&0].g, None);
    }

    #[test]
    fn test_state_machine_context_switch() {
        // Test: G1 running, start G2 → G1 gets stopped (yields) automatically
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create and start G1
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        state_machine.go_start(0, 1, &mut output, 100, stack, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Running);
        assert_eq!(state_machine.m_states[&0].g, Some(1));

        // Create G2 and start it - this should stop (yield) G1 first
        state_machine.go_create(0, 2, &mut output, 200, stack, stack);
        state_machine.go_start(0, 2, &mut output, 300, stack, stack, stack);

        // G1 should now be yielded (Runnable) - context switch is a voluntary yield, not a block
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);
        // G2 should be running
        assert_eq!(state_machine.g_states[&2].status, GoStatus::Running);
        assert_eq!(state_machine.m_states[&0].g, Some(2));
    }

    #[test]
    fn test_state_machine_sequence_numbers() {
        // Test: sequence numbers increment correctly
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create and start G1
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        let seq_before = state_machine.g_states[&1].seq;
        state_machine.go_start(0, 1, &mut output, 100, stack, stack, stack);
        let seq_after_start = state_machine.g_states[&1].seq;

        // Sequence should have incremented
        assert!(seq_after_start > seq_before);

        // Block and unblock
        state_machine.go_block(0, &mut output, 200, 0, stack);
        state_machine.go_unblock(1, &mut output, 300, stack);
        let seq_after_unblock = state_machine.g_states[&1].seq;

        // Sequence should have incremented again
        assert!(seq_after_unblock > seq_after_start);

        // Start again
        state_machine.go_start(0, 1, &mut output, 400, stack, stack, stack);
        let seq_after_restart = state_machine.g_states[&1].seq;

        // Sequence should have incremented again
        assert!(seq_after_restart > seq_after_unblock);
    }

    #[test]
    fn test_state_machine_auto_create_unknown_task() {
        // Test: PollStart for unknown task auto-creates the goroutine
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Start a goroutine that was never created
        assert!(!state_machine.g_states.contains_key(&1));
        state_machine.go_start(0, 1, &mut output, 100, stack, stack, stack);

        // Goroutine should have been auto-created and started
        assert!(state_machine.g_states.contains_key(&1));
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Running);
    }

    #[test]
    fn test_state_machine_unblock_waiting_on_start() {
        // Test: PollStart on a waiting goroutine unblocks it first
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create, start, and block G1
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        state_machine.go_start(0, 1, &mut output, 100, stack, stack, stack);
        state_machine.go_block(0, &mut output, 200, 0, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Waiting);

        // Start G1 again - it should auto-unblock first
        state_machine.go_start(0, 1, &mut output, 300, stack, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Running);
    }

    #[test]
    fn test_state_machine_wake_noop_for_runnable() {
        // Test: WakeEvent for already-runnable G is a no-op
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create G1 (starts in Runnable state)
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);

        let output_len_before = output.len();

        // Wake G1 - should be no-op since already runnable
        state_machine.go_unblock(1, &mut output, 100, stack);

        // No new output should have been generated
        assert_eq!(output.len(), output_len_before);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);
    }

    #[test]
    fn test_state_machine_destroy_starts_if_needed() {
        // Test: TaskTerminate for non-running G starts it first
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create G1 but don't start it
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        assert_eq!(state_machine.g_states[&1].status, GoStatus::Runnable);

        // Destroy G1 - should start it first
        state_machine.go_destroy(0, 1, &mut output, 100, stack, stack, stack);

        // G1 should be gone
        assert!(!state_machine.g_states.contains_key(&1));
    }

    #[test]
    fn test_proc_starts_automatically() {
        // Test: Processor starts automatically when needed
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Create a goroutine - this should auto-start the processor
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);

        // Processor should be running
        assert_eq!(state_machine.p_states[&0].status, ProcStatus::Running);
        assert_eq!(state_machine.m_states[&0].p, Some(0));
    }

    #[test]
    fn test_proc_stop_and_start() {
        // Test: WorkerPark → ProcStop, WorkerUnpark → ProcStart
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        // Start by creating a goroutine (which auto-starts the processor)
        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        assert_eq!(state_machine.p_states[&0].status, ProcStatus::Running);

        // Simulate WorkerPark: stop the processor
        state_machine.proc_stop(0, &mut output, 100);
        assert_eq!(state_machine.p_states[&0].status, ProcStatus::Idle);
        assert_eq!(state_machine.m_states[&0].p, None);

        // Simulate WorkerUnpark: start the processor
        state_machine.proc_start(0, &mut output, 200);
        assert_eq!(state_machine.p_states[&0].status, ProcStatus::Running);
        assert_eq!(state_machine.m_states[&0].p, Some(0));
    }

    #[test]
    fn test_proc_stop_idempotent() {
        // Test: Multiple proc_stop calls are safe
        let mut state_machine = TraceStateMachine::new();
        let mut output = Vec::new();
        let stack = 1u64;

        state_machine.go_create(0, 1, &mut output, 0, stack, stack);
        let output_len_before = output.len();

        // First stop
        state_machine.proc_stop(0, &mut output, 100);
        let output_len_after_first = output.len();
        assert!(output_len_after_first > output_len_before);

        // Second stop (should be no-op)
        state_machine.proc_stop(0, &mut output, 200);
        assert_eq!(output.len(), output_len_after_first);
    }

    #[test]
    fn test_serialization_determinism() {
        // Test: Same events produce identical output across multiple serializations
        // This is critical for trace validation and caching.
        let events = vec![
            OwnedEvent::TaskSpawn {
                timestamp_nanos: 1_000_000,
                task_id: 100,
                location: "src/main.rs:42".to_string(),
            },
            OwnedEvent::TaskSpawn {
                timestamp_nanos: 1_001_000,
                task_id: 200,
                location: "src/main.rs:43".to_string(),
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 1_010_000,
                worker_id: 0,
                task_id: 100,
                location: "src/main.rs:42".to_string(),
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 1_015_000,
                worker_id: 1,
                task_id: 200,
                location: "src/main.rs:43".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 1_100_000,
                worker_id: 0,
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 1_150_000,
                worker_id: 1,
            },
            OwnedEvent::WakeEvent {
                timestamp_nanos: 1_200_000,
                waker_task_id: 200,
                woken_task_id: 100,
            },
            OwnedEvent::PollStart {
                timestamp_nanos: 1_210_000,
                worker_id: 0,
                task_id: 100,
                location: "src/main.rs:42".to_string(),
            },
            OwnedEvent::PollEnd {
                timestamp_nanos: 1_300_000,
                worker_id: 0,
            },
            OwnedEvent::TaskTerminate {
                timestamp_nanos: 1_300_001,
                task_id: 100,
            },
            OwnedEvent::TaskTerminate {
                timestamp_nanos: 1_500_001,
                task_id: 200,
            },
        ];

        // Fixed timestamps for consistency
        let batch_start = SystemTime::UNIX_EPOCH;
        let batch_end = SystemTime::UNIX_EPOCH;

        // Serialize multiple times and compare
        let mut serializer1 = GoTraceSerializer::new();
        let result1 = serializer1
            .serialize(&events, batch_start, batch_end)
            .unwrap();

        let mut serializer2 = GoTraceSerializer::new();
        let result2 = serializer2
            .serialize(&events, batch_start, batch_end)
            .unwrap();

        let mut serializer3 = GoTraceSerializer::new();
        let result3 = serializer3
            .serialize(&events, batch_start, batch_end)
            .unwrap();

        // All outputs must be identical
        assert_eq!(
            result1.data, result2.data,
            "Serialization not deterministic: run 1 != run 2"
        );
        assert_eq!(
            result2.data, result3.data,
            "Serialization not deterministic: run 2 != run 3"
        );

        // Verify output is non-trivial (contains actual events beyond header)
        assert!(
            result1.data.len() > GO_TRACE_HEADER.len() + 100,
            "Output suspiciously small: {} bytes",
            result1.data.len()
        );
    }
}
