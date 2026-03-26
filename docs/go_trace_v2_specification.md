# Go v2 Trace Format Specification

This document provides a detailed specification of Go's execution trace format version 2 (Go 1.22+),
based on analysis of Go's source code in `internal/trace`, `internal/trace/tracev2`, and related packages.

## References

- [Go tracev2 package](https://pkg.go.dev/internal/trace/tracev2@master)
- [Go internal/trace order.go](https://go.dev/src/internal/trace/order.go)
- [Go runtime trace.go](https://go.dev/src/runtime/trace.go)
- [Go execution trace blog](https://go.dev/blog/execution-traces-2024)
- [Execution tracer overhaul design](https://github.com/golang/proposal/blob/master/design/60773-execution-tracer-overhaul.md)

---

## 1. File Header Format

### 1.1 Header Structure

The trace file begins with a 16-byte header:

```
"go 1.XX trace\x00\x00\x00"
```

Where `XX` is the Go minor version number (e.g., "22", "23", "25").

| Offset | Size | Content |
|--------|------|---------|
| 0 | 3 | `"go "` literal prefix |
| 3 | 4-5 | Version string (e.g., `"1.22"`, `"1.23"`) |
| 7-8 | 6 | `" trace"` literal suffix |
| 13-15 | 3 | Null padding bytes `\x00\x00\x00` |

### 1.2 Supported Versions

| Version | Constant | Notes |
|---------|----------|-------|
| 22 | Go122 | First v2 format |
| 23 | Go123 | Adds coroutine events, backwards compatible with 1.22 |
| 25 | Go125 | Adds EvSync batch, EvClockSnapshot |
| 26 | Go126 | Adds EvEndOfGeneration |

### 1.3 Version Detection

```rust
fn read_header(data: &[u8]) -> Result<u8, Error> {
    // Must start with "go 1."
    if !data.starts_with(b"go 1.") {
        return Err("not a Go execution trace");
    }
    // Parse version number
    let version_end = data[5..].iter().position(|&b| b == b' ')?;
    let version_str = &data[5..5+version_end];
    let version: u8 = parse_int(version_str)?;
    // Must end with " trace\x00\x00\x00"
    if &data[5+version_end..16] != b" trace\x00\x00\x00" {
        return Err("invalid header format");
    }
    Ok(version)
}
```

---

## 2. Binary Encoding

### 2.1 Varint (LEB128 Unsigned)

All integer values in the trace use unsigned LEB128 encoding:

```rust
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn read_varint(data: &[u8]) -> Result<(u64, usize), Error> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint overflow");
        }
    }
    Err("unexpected end of varint")
}
```

### 2.2 Event Encoding

Each event consists of:
1. **Event type byte** (1 byte, u8)
2. **Arguments** (0+ varints, determined by event spec)
3. **Optional data** (for events with `HasData`: varint length + raw bytes)
4. **Optional stack** (for events with `IsStack`: varint frame count + 4 varints per frame)

```
[event_type: u8][arg0: varint][arg1: varint]...[argN: varint]
```

---

## 3. Batch Structure

### 3.1 Event Batch (EvEventBatch = 1)

Regular event batches are thread-oriented (M-oriented):

```
[EvEventBatch: u8][gen: varint][m_id: varint][timestamp: varint][size: varint][...events]
```

| Field | Type | Description |
|-------|------|-------------|
| gen | varint | Generation number (starts at 1) |
| m_id | varint | Thread (M) ID, or `MaxUint64` for structural batches |
| timestamp | varint | Base timestamp for this batch (nanoseconds) |
| size | varint | Size of event data following this header |

**Note**: The maximum batch size is 64KB (`MaxBatchSize = 64 << 10`).

### 3.2 Structural Batches

Structural batches use `m_id = MaxUint64` (18446744073709551615) to indicate they are not
associated with a specific thread:

- **Strings batch**: Starts with `EvStrings` (4)
- **Stacks batch**: Starts with `EvStacks` (2)
- **CPU samples batch**: Starts with `EvCPUSamples` (6)
- **Sync batch** (Go 1.25+): Contains `EvSync` + `EvFrequency` + `EvClockSnapshot`

### 3.3 Batch Classification (by first event)

| First Event | Batch Type |
|-------------|------------|
| EvStrings (4) | String table |
| EvStacks (2) | Stack table |
| EvCPUSamples (6) | CPU samples |
| EvFrequency (8) | Sync (pre-1.25) |
| EvSync (50) | Sync (1.25+) |
| Other | Regular event batch |

---

## 4. Event Types

### 4.1 Complete Event Type List

```rust
// Structural events (0-8)
const EV_NONE: u8 = 0;           // Unused
const EV_EVENT_BATCH: u8 = 1;    // [gen, m, time, size]
const EV_STACKS: u8 = 2;         // Stack table section start
const EV_STACK: u8 = 3;          // [id, ...{pc, func_id, file_id, line}]
const EV_STRINGS: u8 = 4;        // String table section start
const EV_STRING: u8 = 5;         // [id, len, data...]
const EV_CPU_SAMPLES: u8 = 6;    // CPU samples section start
const EV_CPU_SAMPLE: u8 = 7;     // [timestamp, m, p, g, stack]
const EV_FREQUENCY: u8 = 8;      // [freq] - timestamp units per second

// Processor events (9-13)
const EV_PROCS_CHANGE: u8 = 9;   // [timestamp, gomaxprocs, stack]
const EV_PROC_START: u8 = 10;    // [timestamp, p, p_seq]
const EV_PROC_STOP: u8 = 11;     // [timestamp]
const EV_PROC_STEAL: u8 = 12;    // [timestamp, p, p_seq, m]
const EV_PROC_STATUS: u8 = 13;   // [timestamp, p, status]

// Goroutine events (14-25)
const EV_GO_CREATE: u8 = 14;           // [timestamp, g, stack, stack]
const EV_GO_CREATE_SYSCALL: u8 = 15;   // [timestamp, g]
const EV_GO_START: u8 = 16;            // [timestamp, g, g_seq]
const EV_GO_DESTROY: u8 = 17;          // [timestamp]
const EV_GO_DESTROY_SYSCALL: u8 = 18;  // [timestamp]
const EV_GO_STOP: u8 = 19;             // [timestamp, reason_string, stack]
const EV_GO_BLOCK: u8 = 20;            // [timestamp, reason_string, stack]
const EV_GO_UNBLOCK: u8 = 21;          // [timestamp, g, g_seq, stack]
const EV_GO_SYSCALL_BEGIN: u8 = 22;    // [timestamp, p_seq, stack]
const EV_GO_SYSCALL_END: u8 = 23;      // [timestamp]
const EV_GO_SYSCALL_END_BLOCKED: u8 = 24; // [timestamp]
const EV_GO_STATUS: u8 = 25;           // [timestamp, g, m, status]

// STW events (26-27)
const EV_STW_BEGIN: u8 = 26;     // [timestamp, kind, stack]
const EV_STW_END: u8 = 27;       // [timestamp]

// GC events (28-38)
const EV_GC_ACTIVE: u8 = 28;            // [timestamp, seq]
const EV_GC_BEGIN: u8 = 29;             // [timestamp, seq, stack]
const EV_GC_END: u8 = 30;               // [timestamp, seq]
const EV_GC_SWEEP_ACTIVE: u8 = 31;      // [timestamp, p]
const EV_GC_SWEEP_BEGIN: u8 = 32;       // [timestamp, stack]
const EV_GC_SWEEP_END: u8 = 33;         // [timestamp, swept, reclaimed]
const EV_GC_MARK_ASSIST_ACTIVE: u8 = 34; // [timestamp, g]
const EV_GC_MARK_ASSIST_BEGIN: u8 = 35;  // [timestamp, stack]
const EV_GC_MARK_ASSIST_END: u8 = 36;    // [timestamp]
const EV_HEAP_ALLOC: u8 = 37;           // [timestamp, bytes]
const EV_HEAP_GOAL: u8 = 38;            // [timestamp, bytes]

// Annotation events (39-44)
const EV_GO_LABEL: u8 = 39;        // [timestamp, label_string]
const EV_USER_TASK_BEGIN: u8 = 40; // [timestamp, task, parent_task, name_string, stack]
const EV_USER_TASK_END: u8 = 41;   // [timestamp, task, stack]
const EV_USER_REGION_BEGIN: u8 = 42; // [timestamp, task, name_string, stack]
const EV_USER_REGION_END: u8 = 43;   // [timestamp, task, name_string, stack]
const EV_USER_LOG: u8 = 44;        // [timestamp, task, key_string, value_string, stack]

// Coroutine events (45-47, Go 1.23+)
const EV_GO_SWITCH: u8 = 45;           // [timestamp, g, g_seq]
const EV_GO_SWITCH_DESTROY: u8 = 46;   // [timestamp, g, g_seq]
const EV_GO_CREATE_BLOCKED: u8 = 47;   // [timestamp, g, stack, stack]

// Extended events (48-52, Go 1.23-1.26+)
const EV_GO_STATUS_STACK: u8 = 48;     // [timestamp, g, m, status, stack]
const EV_EXPERIMENTAL_BATCH: u8 = 49;  // [exp, gen, m, time, size, data...]
const EV_SYNC: u8 = 50;                // [...EvFrequency|EvClockSnapshot]
const EV_CLOCK_SNAPSHOT: u8 = 51;      // [timestamp, mono, sec, nsec]
const EV_END_OF_GENERATION: u8 = 52;   // [] (Go 1.26+)
```

### 4.2 Argument Type Annotations

Event arguments can have type annotations in the format `name_type`:

| Type | Description |
|------|-------------|
| `seq` | Sequence number |
| `pstatus` | Processor status (ProcStatus enum) |
| `gstatus` | Goroutine status (GoStatus enum) |
| `g` | Goroutine ID |
| `m` | Thread (M) ID |
| `p` | Processor (P) ID |
| `string` | String table ID |
| `stack` | Stack table ID |
| `value` | Raw uint64 value |
| `task` | Task ID |

---

## 5. Status Enums

### 5.1 GoStatus (Goroutine Status)

```rust
#[repr(u8)]
enum GoStatus {
    Bad = 0,       // Invalid state (error if seen)
    Runnable = 1,  // Ready to run, waiting for P
    Running = 2,   // Currently executing
    Syscall = 3,   // In system call
    Waiting = 4,   // Blocked, waiting for something
}
```

### 5.2 ProcStatus (Processor Status)

```rust
#[repr(u8)]
enum ProcStatus {
    Bad = 0,              // Invalid state
    Running = 1,          // Executing on an M
    Idle = 2,             // Not running
    Syscall = 3,          // M in syscall with this P
    SyscallAbandoned = 4, // P was stolen (special case)
}
```

---

## 6. String and Stack Tables

### 6.1 String Table Format

String batches start with `EvStrings` followed by `EvString` entries:

```
[EvStrings: u8]
[EvString: u8][id: varint][len: varint][data: bytes...]
[EvString: u8][id: varint][len: varint][data: bytes...]
...
```

String IDs are referenced by other events via the `string` argument type.

### 6.2 Stack Table Format

Stack batches start with `EvStacks` followed by `EvStack` entries:

```
[EvStacks: u8]
[EvStack: u8][id: varint][frame_count: varint]
    [pc: varint][func_id: varint][file_id: varint][line: varint]
    [pc: varint][func_id: varint][file_id: varint][line: varint]
    ...
```

| Field | Description |
|-------|-------------|
| id | Unique stack ID (referenced by `stack` arguments) |
| frame_count | Number of frames (max 128, `MaxFramesPerStack`) |
| pc | Program counter for frame |
| func_id | String ID for function name |
| file_id | String ID for file path |
| line | Line number |

**Validation**: Frames (except the first, which can be zero) must have non-empty func, file, PC, and line.

---

## 7. Generations and Sync Events

### 7.1 Generation Concept

Traces are divided into **generations** for streaming analysis:
- Each generation is self-contained with its own string/stack tables
- Generation boundaries occur at size thresholds (~16 MiB) or wall-clock limits
- Generation numbers start at 1 and increment monotonically

### 7.2 Sync Events

**Go 1.22-1.24** (Pre-sync batch):
```
[EvEventBatch][gen][MaxUint64][time][size]
[EvFrequency][freq]
```

**Go 1.25+** (Sync batch):
```
[EvEventBatch][gen][MaxUint64][time][size]
[EvSync]
[EvFrequency][freq]
[EvClockSnapshot][timestamp][mono][sec][nsec]
```

**Go 1.26+** (End of generation):
Each generation ends with:
```
[EvEndOfGeneration]
```

### 7.3 First Generation Requirements

The trace MUST start with a sync event. The trace reader:
- Always produces a Sync event as the first event
- Always produces a Sync event as the last event

### 7.4 Frequency Event

The `EvFrequency` event specifies timestamp units per second:

```
[EvFrequency: u8][freq: varint]
```

Common value: `15625000` (approximately 64ns granularity).

All timestamps in the trace are expressed in these units.

---

## 8. Goroutine Lifecycle State Machine

### 8.1 Valid State Transitions

```
                    +---------+
                    |  (new)  |
                    +---------+
                         |
                    GoCreate / GoCreateSyscall / GoCreateBlocked
                         |
                         v
    +----------+    +-----------+    +----------+
    |          |<---|  Runnable |<---|          |
    | Waiting  |    +-----------+    | Syscall  |
    |          |--->|           |--->|          |
    +----------+    |  Running  |    +----------+
         ^          +-----------+         ^
         |               |                |
         |          GoDestroy             |
         |               |                |
         |               v                |
         |          +---------+           |
         +----------|  (dead) |-----------+
                    +---------+
```

### 8.2 Transition Events

| From | To | Event(s) |
|------|----|----------|
| (new) | Runnable | `GoCreate`, `GoCreateSyscall` |
| (new) | Waiting | `GoCreateBlocked` |
| Runnable | Running | `GoStart` |
| Running | Runnable | `GoStop` |
| Running | Waiting | `GoBlock` |
| Running | Syscall | `GoSyscallBegin` |
| Running | (dead) | `GoDestroy` |
| Waiting | Runnable | `GoUnblock` |
| Syscall | Running | `GoSyscallEnd` |
| Syscall | Runnable | `GoSyscallEndBlocked` |
| Syscall | (dead) | `GoDestroySyscall` |

### 8.3 GoStatus Events (Generation Start)

At the start of each generation, `GoStatus` events enumerate all existing goroutines:

```
[EvGoStatus: u8][timestamp: varint][g: varint][m: varint][status: varint]
```

- `g`: Goroutine ID
- `m`: Thread ID the goroutine is bound to (or 0/MaxUint64 if unbound)
- `status`: Current GoStatus value

**Critical Rule**: `GoStatus` events can ONLY introduce new goroutines in the first generation.
After the first generation, all goroutines must have been previously created.

---

## 9. Processor Lifecycle State Machine

### 9.1 Valid State Transitions

```
                    +---------+
                    |  Idle   |<----+
                    +---------+     |
                         |          |
                    ProcStart       |
                         |     ProcStop / ProcSteal
                         v          |
                    +---------+     |
                    | Running |-----+
                    +---------+
                         |
                    GoSyscallBegin
                         |
                         v
                    +---------+
                    | Syscall |
                    +---------+
                         |
            +------------+------------+
            |                         |
       GoSyscallEnd              ProcSteal
            |                         |
            v                         v
       +---------+               +---------+
       | Running |               |  Idle   |
       +---------+               +---------+
```

### 9.2 ProcStatus Events

At generation start, `ProcStatus` events enumerate all processors:

```
[EvProcStatus: u8][timestamp: varint][p: varint][status: varint]
```

---

## 10. Sequence Numbers

### 10.1 Purpose

Sequence numbers establish a **partial order** over events, compensating for potentially unreliable
timestamps. They ensure correct event ordering even when clock skew occurs.

### 10.2 Rules

1. Each goroutine and processor maintains its own sequence counter
2. Sequence numbers reset to 0 at the start of each generation
3. A sequence number `seq` is valid if it equals `previous_seq + 1`

### 10.3 Events Using Sequences

| Event | Sequence Field |
|-------|----------------|
| `GoStart` | `g_seq` - goroutine sequence |
| `GoUnblock` | `g_seq` - target goroutine sequence |
| `ProcStart` | `p_seq` - processor sequence |
| `ProcSteal` | `p_seq` - target processor sequence |
| `GoSyscallBegin` | `p_seq` - processor sequence |
| `GoSwitch` | `g_seq` - target goroutine sequence |
| `GoSwitchDestroy` | `g_seq` - target goroutine sequence |

### 10.4 Validation

```rust
fn validate_sequence(expected: u64, actual: u64) -> bool {
    actual == expected + 1
}
```

If a sequence number doesn't match, the event cannot be processed yet (deferred).

---

## 11. Scheduling Context Requirements

### 11.1 Context Structure

```rust
struct SchedContext {
    m: Option<ThreadId>,   // Current thread
    p: Option<ProcId>,     // Current processor
    g: Option<GoId>,       // Current goroutine
}
```

### 11.2 Event Requirements

Each event has scheduling context requirements:

| Constraint | Meaning |
|------------|---------|
| `mustHave` | Context MUST have this resource bound |
| `mayHave` | Context MAY have this resource bound |
| `mustNotHave` | Context MUST NOT have this resource bound |

### 11.3 Event Context Table

| Event | M | P | G |
|-------|---|---|---|
| GoCreate | mustHave | mustHave | mustNotHave |
| GoStart | mustHave | mustHave | mustNotHave |
| GoStop | mustHave | mustHave | mustHave |
| GoBlock | mustHave | mustHave | mustHave |
| GoUnblock | mustHave | mayHave | mayHave |
| GoDestroy | mustHave | mustHave | mustHave |
| GoSyscallBegin | mustHave | mustHave | mustHave |
| GoSyscallEnd | mustHave | mayHave | mustHave |
| GoSyscallEndBlocked | mustHave | mayHave | mustHave |
| ProcStart | mustHave | mustNotHave | mayHave |
| ProcStop | mustHave | mustHave | mayHave |
| ProcSteal | mustHave | mayHave | mayHave |
| HeapAlloc | mustHave | mustHave | mayHave |
| HeapGoal | mustHave | mustHave | mayHave |
| UserTaskBegin | mustHave | mustHave | mustHave |
| UserTaskEnd | mustHave | mustHave | mustHave |
| UserRegionBegin | mustHave | mustHave | mustHave |
| UserRegionEnd | mustHave | mustHave | mustHave |
| UserLog | mustHave | mustHave | mustHave |

---

## 12. Validation Errors

### 12.1 Fatal Errors (Trace Rejected)

| Error | Cause |
|-------|-------|
| `"not a Go execution trace"` | Header doesn't match expected format |
| `"unknown or unsupported trace version"` | Version not in supported list |
| `"expected a thread but didn't have one"` | Event requires M, none bound |
| `"expected a proc but didn't have one"` | Event requires P, none bound |
| `"expected a goroutine but didn't have one"` | Event requires G, none bound |
| `"event X for goroutine that doesn't exist"` | G referenced before creation |
| `"event X for proc that doesn't exist"` | P referenced before creation |
| `"tried to create goroutine that already exists"` | Duplicate GoCreate |
| `"inconsistent status for goroutine"` | State transition invalid |
| `"inconsistent status for proc"` | P state transition invalid |
| `"failed to advance: can't make sequence"` | Sequence number mismatch |
| `"broken trace: frontier is empty"` | No events to process |
| `"broken trace: failed to advance"` | All events failed validation |
| `"task ID conflict"` | Duplicate task ID |
| `"misuse of region in goroutine"` | Region end without matching begin |

### 12.2 Deferred Events (Not Errors)

When validation returns `(false, nil)`, the event is deferred:
- Sequence number not yet valid (waiting for prior event)
- Referenced resource doesn't exist yet
- State machine not in required precondition

The trace reader tries other events before returning to deferred ones.

### 12.3 Timestamp Validation

Timestamps must be monotonically increasing. If violated:
- The reader corrects: `if timestamp <= last_ts { timestamp = last_ts + 1 }`
- This maintains ordering based on sequence numbers

---

## 13. Minimal Valid Trace

### 13.1 Absolute Minimum (Go 1.22-1.24)

```
Header: "go 1.22 trace\x00\x00\x00"

Batch 1 (Sync):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size=N]
  [EvFrequency][freq=15625000]

Batch 2 (Empty strings):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size=N]
  [EvStrings]

Batch 3 (Empty stacks):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size=N]
  [EvStacks]
```

### 13.2 Minimal with Goroutine Activity

```
Header: "go 1.22 trace\x00\x00\x00"

Batch 1 (Sync):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size]
  [EvFrequency][freq=15625000]

Batch 2 (Strings):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size]
  [EvStrings]
  [EvString][id=1][len=4]["main"]
  [EvString][id=2][len=7]["main.go"]

Batch 3 (Stacks):
  [EvEventBatch][gen=1][m=MaxUint64][time=0][size]
  [EvStacks]
  [EvStack][id=1][frames=1][pc=0x1000][func=1][file=2][line=10]

Batch 4 (Events on M=0):
  [EvEventBatch][gen=1][m=0][time=1000][size]
  [EvProcsChange][dt=0][procs=1][stack=0]
  [EvProcStatus][dt=1][p=0][status=Idle]
  [EvProcStart][dt=2][p=0][p_seq=1]
  [EvGoCreate][dt=3][g=1][stack=1][stack=0]
  [EvGoStart][dt=4][g=1][g_seq=1]
  [EvGoStop][dt=100][reason=0][stack=0]
  [EvGoStart][dt=101][g=1][g_seq=2]
  [EvGoDestroy][dt=200]
  [EvProcStop][dt=201]
```

---

## 14. Common Mistakes

### 14.1 Missing Sync/Frequency Event

**Symptom**: `"broken trace: frontier is empty"`

**Fix**: Ensure first batch contains `EvFrequency` (or `EvSync` + `EvFrequency` for Go 1.25+).

### 14.2 Wrong Event Order

**Symptom**: `"event X for goroutine that doesn't exist"`

**Fix**: Ensure `GoCreate` precedes `GoStart`, `GoBlock`, etc.

### 14.3 Invalid State Transition

**Symptom**: `"inconsistent status for goroutine"`

**Fix**: Follow the state machine. Can't `GoStart` a `Running` goroutine.

### 14.4 Sequence Number Mismatch

**Symptom**: `"failed to advance: can't make sequence"`

**Fix**: Sequence numbers must increment by exactly 1. Track per-resource.

### 14.5 Missing Context

**Symptom**: `"expected a proc but didn't have one"`

**Fix**: Ensure `ProcStart` occurs before goroutine events that require P.

### 14.6 Incomplete Trace

**Symptom**: `"expected batch event (EventBatch), got Invalid(X)"`

**Cause**: Trace file truncated (e.g., program killed with Ctrl+C).

**Fix**: Allow program to exit gracefully so `trace.Stop()` runs.

### 14.7 Batch Size Exceeded

**Symptom**: Parser error on large batches

**Fix**: Keep batches under 64KB (`MaxBatchSize`). Split into multiple batches.

---

## 15. Delta Timestamps

### 15.1 Batch Base Timestamp

Each batch has a base timestamp. Events within the batch use **delta timestamps** relative to
this base (or to the previous event's timestamp).

### 15.2 Delta Encoding

The first argument of timed events is typically `dt` (delta time):

```
actual_timestamp = batch_base_time + dt
```

Or for events after the first in a batch:

```
actual_timestamp = previous_event_timestamp + dt
```

### 15.3 Example

```
Batch: base_time = 1000000
  Event 1: dt=0    -> timestamp = 1000000
  Event 2: dt=100  -> timestamp = 1000100
  Event 3: dt=50   -> timestamp = 1000150
```

---

## 16. Timestamp Units

### 16.1 Frequency Interpretation

```rust
let freq = 15625000; // From EvFrequency
let timestamp_ns = (raw_timestamp * 1_000_000_000) / freq;
```

### 16.2 Common Frequencies

| Platform | Typical Frequency | Resolution |
|----------|-------------------|------------|
| Linux | 15625000 | ~64ns |
| macOS | 1000000000 | 1ns |
| Windows | Varies | System-dependent |

---

## 17. Go 1.25+ Clock Snapshot

### 17.1 EvClockSnapshot Format

```
[EvClockSnapshot: u8][timestamp: varint][mono: varint][sec: varint][nsec: varint]
```

| Field | Description |
|-------|-------------|
| timestamp | Trace timestamp at snapshot |
| mono | Monotonic clock reading (nanoseconds) |
| sec | Wall clock seconds (Unix epoch) |
| nsec | Wall clock nanoseconds |

### 17.2 Purpose

Enables correlation between trace timestamps and wall-clock time, useful for correlating
with external systems.

---

## 18. Checklist for Valid Trace Output

1. **Header**
   - [ ] Exactly 16 bytes
   - [ ] Format: `"go 1.XX trace\x00\x00\x00"`
   - [ ] Version is supported (22, 23, 25, 26)

2. **First Batch (Sync)**
   - [ ] `m_id = MaxUint64`
   - [ ] Contains `EvFrequency` (or `EvSync` + `EvFrequency` for 1.25+)
   - [ ] Frequency value is reasonable (e.g., 15625000)

3. **String Table**
   - [ ] Batch with `m_id = MaxUint64`
   - [ ] Starts with `EvStrings`
   - [ ] All referenced string IDs are defined
   - [ ] No duplicate string IDs

4. **Stack Table**
   - [ ] Batch with `m_id = MaxUint64`
   - [ ] Starts with `EvStacks`
   - [ ] All referenced stack IDs are defined
   - [ ] Frames have valid func/file/line (except frame 0)
   - [ ] Frame count <= 128

5. **Event Batches**
   - [ ] Valid batch header with proper `m_id`
   - [ ] Batch size <= 64KB
   - [ ] Timestamps are monotonically increasing
   - [ ] All event arguments are valid varints

6. **Goroutine Lifecycle**
   - [ ] `GoCreate` before any other G event
   - [ ] Valid state transitions only
   - [ ] Sequence numbers increment by 1
   - [ ] Context requirements satisfied

7. **Processor Lifecycle**
   - [ ] `ProcStatus` at generation start OR `ProcStart` before use
   - [ ] Valid state transitions only
   - [ ] `ProcStart` before goroutine events requiring P

8. **Status Events (Generation Start)**
   - [ ] All active goroutines have `GoStatus`
   - [ ] All active processors have `ProcStatus`
   - [ ] Status values match actual states

9. **Cross-References**
   - [ ] All string IDs reference valid strings
   - [ ] All stack IDs reference valid stacks
   - [ ] All goroutine IDs reference created goroutines
   - [ ] All processor IDs reference created processors
