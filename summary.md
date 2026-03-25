# Tokio Timeline Go Trace Implementation Summary

## What Was Built

Implemented a Go trace v2 format serializer (`go_trace.rs`) that converts Tokio runtime events into Go's execution trace format for visualization in Datadog's Timeline View.

### Key Components

1. **State Machine** (`TraceStateMachine`): Tracks goroutine (G), processor (P), and thread (M) states to emit valid Go trace events
   - Handles state transitions: Runnable → Running → Waiting
   - Maps Tokio tasks to goroutines, workers to M/P pairs

2. **Event Mapping**:
   - `TaskSpawn` → `GoCreate` (creates goroutine)
   - `PollStart` → `GoStart` (goroutine starts running)
   - `PollEnd` → `GoBlock` (goroutine yields/waits)
   - `WakeEvent` → `GoUnblock` (wakes waiting goroutine)
   - `TaskTerminate` → `GoDestroy` (goroutine exits)

3. **Multi-M Support**: Each Tokio worker maps to a separate M/P pair, enabling concurrent task visualization across multiple lanes

4. **Uploader**: Sends traces to Datadog's `/profiling/v1/input` endpoint with proper multipart encoding and metadata

## What Works

- Generated traces **pass `go tool trace` validation** completely
- Traces show correct multi-M concurrent execution in `go tool trace -d=parsed`
- Uploads succeed to Datadog agent (HTTP 200)
- Real Go traces (`~/go.trace`) uploaded the same way **do show timeline data**

## Current Issue

**Datadog shows "No timeline data available for this profile"** for our generated traces, even though:
- The trace format is valid (passes Go's trace parser)
- The upload succeeds
- Real Go traces work when uploaded identically

### Key Differences From Real Go Traces

| Aspect | Real Go Trace | Our Trace |
|--------|---------------|-----------|
| Stack traces | Has actual stacks (stack=1,2,3...) | All stack=0 |
| String table | Has function names, file paths | Empty/minimal |
| reason_string | Maps to strings like "sleep" | All reason_string=0 |
| Runtime events | HeapAlloc, ProcsChange, STW, etc. | None |
| GoStatus | Establishes existing goroutines | We emit GoStatus for G=1 only |

### Attempted Fixes (Did Not Resolve)

1. ✅ Changed form field name from "execution-trace" to "go.trace" (matches dd-trace-go)
2. ✅ Changed frequency from 1GHz to 15.625MHz (matches Go's trace frequency)
3. ✅ Added `GoStatus` event to establish main goroutine
4. ✅ Changed `ProcStatus` from Idle to Running
5. ✅ Used monotonic timestamps matching Go's scale (~64 trillion ticks)
6. ✅ Fixed goroutine ID mapping (start at 2, reserve 1 for main)
7. ❌ Tried bundling with cpu.pprof - still blank
8. ❌ Tried various upload intervals - still blank

## Hypothesis

Datadog's timeline visualization likely requires **stack traces** to render goroutine activity. Real Go traces include full stack information for each event, while we emit `stack=0` everywhere. The backend may be filtering out events without valid stack references.

## Files Modified

- `datadog-opentelemetry/src/tokio_timeline/serializer/go_trace.rs` - Main serializer with state machine
- `datadog-opentelemetry/src/tokio_timeline/serializer/pprof_timeline.rs` - Changed filename to cpu.pprof
- `datadog-opentelemetry/src/tokio_timeline/uploader.rs` - Fixed form field naming
- `datadog-opentelemetry/src/tokio_timeline/worker.rs` - Added debug logging
- `datadog-opentelemetry/examples/tokio_timeline/src/main.rs` - Test configuration

## Next Steps to Investigate

1. **Add stack traces**: Emit actual stack IDs with function/file/line info in the string table
2. **Add reason strings**: Populate reason_string with meaningful values ("sleep", "channel", etc.)
3. **Contact Datadog**: Ask what specific events/fields the timeline visualization requires
4. **Compare binary format**: Do byte-level comparison of real vs generated traces to find subtle differences
