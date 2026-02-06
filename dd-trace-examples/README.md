# Datadog OpenTelemetry Example

This example demonstrates how to use `datadog-opentelemetry` with the `tracing` crate and `tracing-opentelemetry` bridge in an Axum HTTP server.

## Features

- **Datadog OpenTelemetry Integration**: Uses the `datadog-opentelemetry` crate for sending traces to Datadog
- **Tracing Bridge**: Demonstrates the `tracing-opentelemetry` bridge for seamless integration
- **HTTP Server**: Built with Axum framework
- **Structured Logging**: Uses the `tracing` crate for structured logging
- **Custom Spans**: Shows how to create custom spans with attributes
- **REST API**: Includes endpoints for user management and health checks

## Prerequisites

1. **Datadog Agent**: Make sure you have a Datadog agent running locally or accessible
2. **Rust**: Ensure you have Rust 1.84.1+ installed

## Running the Example

### 1. Start the Datadog Agent (if running locally)

```bash
# Using Docker
docker run -d --name datadog-agent \
  -e DD_API_KEY=your_api_key \
  -e DD_APM_ENABLED=true \
  -e DD_APM_NON_LOCAL_TRAFFIC=true \
  -p 8126:8126 \
  datadog/agent:latest

# Or using the official install script
DD_API_KEY=your_api_key DD_APM_ENABLED=true bash -c "$(curl -L https://s1.datadoghq.com/install_script_agent7.sh)"
```

### 2. Run the Example

```bash
# From the examples directory
cargo run

# Or from the workspace root
cargo run -p dd-trace-examples
```

The server will start on `http://localhost:3000`

### 3. Test the API

```bash
# Health check
curl http://localhost:3000/health

# Get user by ID
curl http://localhost:3000/users/123

# Create a new user
curl -X POST http://localhost:3000/users \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'
```

## Configuration

The example is configured to send traces to `http://localhost:8126/v0.5/traces` (default Datadog agent endpoint). You can modify the configuration in the `main()` function:

```rust
let pipeline = DatadogPipeline::new()
    .with_service_name("dd-trace-example")
    .with_service_version("1.0.0")
    .with_env("development")
    .with_trace_endpoint("http://localhost:8126/v0.5/traces")
    .build()?;
```

## Key Components

### 1. Datadog Pipeline Setup

```rust
use datadog_opentelemetry::DatadogPipeline;

let pipeline = DatadogPipeline::new()
    .with_service_name("dd-trace-example")
    .with_service_version("1.0.0")
    .with_env("development")
    .build()?;
```

### 2. Tracing Integration

```rust
use tracing::{info, instrument};
use tracing_opentelemetry::OpenTelemetrySpanExt;

#[instrument(skip(tracer))]
async fn get_user(Path(id): Path<u32>, tracer: Extension<Tracer>) -> Json<ApiResponse<User>> {
    let span = tracer.start("get_user");
    span.set_attribute(opentelemetry::KeyValue::new("user.id", id.to_string()));
    // ... function logic
    span.end();
}
```

### 3. Global Tracer Setup

```rust
use opentelemetry::global;

let tracer = pipeline.tracer();
global::set_tracer_provider(pipeline.trace_provider());
```

## What You'll See

1. **Console Logs**: Structured logging output showing the application flow
2. **Datadog Traces**: Spans and traces sent to your Datadog agent
3. **Custom Attributes**: User ID, name, and email attributes on spans
4. **Performance Metrics**: Timing information for each operation

## Troubleshooting

### Common Issues

1. **Connection Refused**: Make sure the Datadog agent is running and accessible
2. **Permission Denied**: Check that the agent endpoint is correct and accessible
3. **No Traces in Datadog**: Verify your API key and agent configuration

### Debug Mode

The example includes debug logging for the datadog-opentelemetry crate:

```rust
tracing_subscriber::fmt()
    .with_env_filter("info,datadog_opentelemetry=debug")
    .init();
```

## Next Steps

- Modify the service name, version, and environment
- Add more custom attributes to spans
- Implement error handling and error spans
- Add metrics collection
- Configure sampling and filtering rules
