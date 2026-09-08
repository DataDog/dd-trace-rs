# Repository Structure

This is a Cargo workspace. The production crates are `datadog-trace-propagation` and
`datadog-opentelemetry` (which depends on and re-exports the former as its `propagation` module);
the examples under `datadog-opentelemetry/examples/` are separate workspace members with
`publish = false`.

```text
dd-trace-rs/
├── datadog-trace-propagation/   # Trace context propagation (Datadog, W3C, B3 formats)
│   └── src/
│       ├── lib.rs               # DatadogCompositePropagator and re-exports
│       ├── b3.rs / b3multi.rs   # B3 propagation formats
│       ├── baggage.rs           # W3C Baggage propagation
│       ├── context.rs           # SpanContext, Tracestate, span-link handling
│       ├── datadog.rs           # Datadog x-datadog-* propagation
│       ├── tracecontext.rs      # W3C Trace Context propagation
│       ├── carrier.rs           # Injector/Extractor carrier traits
│       ├── sampling.rs          # Sampling priority/mechanism primitives
│       └── configuration.rs     # TracePropagationStyle/BehaviorExtract enums
├── datadog-opentelemetry/       # Main crate — Datadog OpenTelemetry SDK
│   ├── src/
│   │   ├── lib.rs               # Public API entry point (tracing(), metrics(), logs() builders)
│   │   ├── core/                # Internal: config, sampling decisions, telemetry, error types
│   │   ├── mappings/            # OTel → Datadog span transformation
│   │   └── sampling/            # Sampler implementations (rules, rate, agent-based)
│   ├── tests/
│   │   ├── integration_tests/   # Integration tests (require Docker test agent)
│   │   └── snapshots/           # JSON snapshot fixtures for integration tests
│   ├── benches/                 # Criterion benchmarks
│   └── examples/
│       ├── propagator/          # HTTP server example
│       └── simple_tracing/      # Minimal tracing example
├── scripts/                     # Release, license, and build automation
│   ├── pack-system-tests-artifact.sh  # Stable entry point for system-test builds
│   └── check-trace-propagation-isolation.sh  # CI guardrail for the propagation crate
├── docs/                        # Architecture documentation
├── .config/                     # Tool config (commitlint, nextest profiles)
└── .github/                     # CI workflows and issue templates
```

**Propagation crate independence**: `datadog-trace-propagation` must not depend on any `libdd-*`
crate (normal, build, or dev edges). `datadog-opentelemetry` re-exports it as
`datadog_opentelemetry::propagation` and converts between its sampling primitives and the libdd
sampling types used by the sampler and span processor. CI enforces this with
`scripts/check-trace-propagation-isolation.sh` (see the `lint.yaml` workflow).

**Key visibility rule**: `core` is `pub(crate)` by default; it is re-exported as `pub` only when the
`test-utils` feature is enabled (used by integration tests). Only `configuration` and `log` modules
are always public.

**Feature flags** (in `datadog-opentelemetry/Cargo.toml`):

- `metrics-grpc` / `metrics-http` — OTLP transport for metrics (default: grpc)
- `logs-grpc` / `logs-http` — OTLP transport for logs (default: grpc)
- `test-utils` — exposes internal helpers and pulls in test dependencies; never enable in production
  builds
- `_unstable_propagation`: deprecated, has no effect. Propagation is now always available via the
  `datadog-trace-propagation` re-export; enabling the feature emits a build-time warning

## System-test build entry point

`scripts/pack-system-tests-artifact.sh` is the stable entry point for packaging workspace source
for [DataDog/system-tests](https://github.com/DataDog/system-tests).

System tests build `ddtrace-rs-client` inside Docker against a local copy of `datadog-opentelemetry`
(path dependency, not a published crate). The script reads `[workspace] members` from `Cargo.toml`,
expands any glob patterns, deduplicates nested paths, and copies the unique root directories along
with the workspace-level files Cargo needs. New workspace crates are picked up automatically.

```text
# Pack source into ./binaries/dd-trace-rs (default)
./scripts/pack-system-tests-artifact.sh

# Specify a custom output directory
./scripts/pack-system-tests-artifact.sh /path/to/output
```

CI runs this in the `build-artifacts` job and uploads the result as the `system_tests_binaries`
artifact. The system-test Dockerfile copies the source into the container and compiles
`ddtrace-rs-client` against it.

## datadog-opentelemetry

The `datadog-opentelemetry` crate is organized into several internal modules, each with distinct
responsibilities in the tracing pipeline:

- Core library features in `core::`
  - Configuration
  - Instrumentation telemetry
  - Logging
  - Constant definitions
- Distributed context propagation in `propagation`
- Span/Trace Sampling in `sampling`
- OpenTelemetry SDK compatible components at the root level
  - The Span processor/exporter
  - A trace registry that tracks extra span information
  - A compatibility layer for the Propagator
  - A compatibility layer for the Sampler

## Span tracking

### DatadogSpanProcessor

DatadogSpanProcessor implements the OpenTelemetry SpanProcessor trait and serves as the central
orchestrator for span lifecycle management. It coordinates between the registry, exporter, and other
subsystems.

Responsibilities:

- Hook into OpenTelemetry span creation (on_start) and completion (on_end)
- Register spans with TraceRegistry to track open/finished spans
- Add propagation data (sampling decisions, origin, tags) to completed traces
- Trigger export of complete or partial traces
- Coordinate shutdown of dependent components

### TraceRegistry

TraceRegistry maintains state for all in-flight traces using a sharded architecture with 64 shards
for concurrent access. Each shard contains a HashMap of traces indexed by trace ID.

Responsibilities:

- Track open span count per trace
- Store finished spans until trace is complete
- Store trace propagation data (sampling decision, origin, tags)
- Determine when to flush traces (all spans finished or partial flush threshold)

### DatadogExporter

DatadogExporter buffers span data and manages export to the Datadog Agent via a dedicated worker
thread.

Responsibilities:

- Buffer traces in memory until flush conditions are met
- Provide non-blocking export API

Flush conditions:

- Span count exceeds SPAN_FLUSH_THRESHOLD (3000 spans)
- Time since last flush exceeds MAX_BATCH_TIME (1 second)
- Force flush requested
- Shutdown initiated
