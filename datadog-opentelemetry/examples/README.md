# Examples

## simple_tracing

Demonstrates basic usage of Datadog OpenTelemetry tracing. Creates nested spans and demonstrates
tracer initialization and shutdown.

```bash
cargo run -p simple_tracing
```

## propagator

HTTP server that demonstrates trace context propagation between services. Shows how to extract trace
context from incoming requests and inject it into outgoing requests.

```bash
cargo run -p propagator
```

The server runs on `http://localhost:3000` with endpoints:

- `/health` - Health check endpoint
- `/echo` - Echo request body
- `/jump` - Makes outbound request to port 3001

It also shows where the tracer's own diagnostics go. They are emitted through `tracing` under the
`datadog_opentelemetry` target, so the subscriber built in `init_logs` decides where they go: the
console through `fmt`, while the OpenTelemetry bridge excludes the trace transport's own crates so a
failed export cannot produce further records to export. How verbose they are is a separate setting,
controlled by `DD_LOG_LEVEL` — this example sets `Debug` in code. The subscriber is installed
before the tracer, because diagnostics emitted before one exists are printed rather than routed.
