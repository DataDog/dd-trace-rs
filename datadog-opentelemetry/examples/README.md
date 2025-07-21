# Examples

## simple_tracing

Demonstrates basic usage of Datadog OpenTelemetry tracing. Creates nested spans and demonstrates tracer initialization and shutdown.

```bash
cargo run -p simple_tracing
```

## propagator

HTTP server that demonstrates trace context propagation between services. Shows how to extract trace context from incoming requests and inject it into outgoing requests.

```bash
cargo run -p propagator
```

The server runs on `http://localhost:3000` with endpoints:
- `/health` - Health check endpoint
- `/echo` - Echo request body 
- `/jump` - Makes outbound request to port 3001
