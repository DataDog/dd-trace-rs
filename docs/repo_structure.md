# Repo structure

Currently the repository contains only one crate, `datadog-opentelemetry`

## datadog-opentelemetry

The `datadog-opentelemetry` crate is organized into several internal modules, each with distinct responsibilities in the tracing pipeline:

* Core library features in `core::`
    * Configuration
    * Instrumentation telemetry
    * Logging
    * Constant definitions
* Distributed context propagation in `propagation`
* Span/Trace Sampling in `sampling`
* Opentelemetry SDK compatible components at the root level
    * The Span processor/exporter
    * A trace registry that tracks extra span information
    * A compatibility layer for the Propagator
    * A compatibility layer for the Sampler


## Span tracking 

### DatadogSpanProcessor
DatadogSpanProcessor implements the OpenTelemetry SpanProcessor trait and serves as the central orchestrator for span lifecycle management. It coordinates between the registry, exporter, and other subsystems.

Responsibilities:
* Hook into OpenTelemetry span creation (on_start) and completion (on_end)
* Register spans with TraceRegistry to track open/finished spans
* Add propagation data (sampling decisions, origin, tags) to completed traces
* Trigger export of complete or partial traces
* Coordinate shutdown of dependent components

### TraceRegistry
TraceRegistry maintains state for all in-flight traces using a sharded architecture with 64 shards for concurrent access. Each shard contains a HashMap of traces indexed by trace ID.

Responsibilities:
* Track open span count per trace
* Store finished spans until trace is complete
* Store trace propagation data (sampling decision, origin, tags)
* Determine when to flush traces (all spans finished or partial flush threshold)

### DatadogExporter
DatadogExporter buffers span data and manages export to the Datadog Agent via a dedicated worker thread.

Responsibilities:
* Buffer traces in memory until flush conditions are met
* Provide non-blocking export API

Flush Conditions:
* Span count exceeds SPAN_FLUSH_THRESHOLD (3000 spans)
* Time since last flush exceeds MAX_BATCH_TIME (1 second)
* Force flush requested
* Shutdown initiated
