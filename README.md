# dd-trace-rs

`dd-trace-rs` is a Rust library for tracing and monitoring applications using Datadog. It provides OpenTelemetry compatibility with Datadog-specific features and optimizations.

> ‼️ **PREVIEW**: This repository is still in preview. Use at your own risk.

## Usage

The `datadog-opentelemetry` crate provides an easy to use override for the rust opentelemetry-sdk.


### Initialization

```rust
use std::time::Duration;

fn main() {
    // This picks up env var configuration and other datadog configuration sources
    let tracer_provider = datadog_opentelemetry::tracing()
        .init();

    // Your code
    // Now use standard OpenTelemetry APIs
    use opentelemetry::global;
    use opentelemetry::trace::Tracer;

    let tracer = global::tracer("my-service");
    let span = tracer.start("my-operation");
    // ... do work ...

    // Shutdown the tracer to flush the remaining data
    tracer_provider.shutdown_with_timeout(Duration::from_secs(1)).expect("tracer shutdown error");
}
```

### Tracing

To trace functions, you can either use the `opentelemetry` crate's [API](https://docs.rs/opentelemetry/0.30.0/opentelemetry/trace/index.html) or the `tracing` crate [API](https://docs.rs/tracing/0.1.41/tracing/) with the `tracing-opentelemetry` [bridge](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/).

### Configuration

* `DD_SERVICE`
    - default: "unnamed-rust-service"
* `DD_ENV`
* `DD_VERSION`
* `DD_TAGS`
    - format: "tag_1:value1,tag_2:value2"
* `DD_TRACE_AGENT_URL`
    - format: "http://<agent_url>:<agent_port>"
* `DD_TRACE_SAMPLING_RULES`
    - format: 
* `DD_TRACE_RATE_LIMIT`
    - format: "<int>"
* `DD_TRACE_ENABLED`
    - format: "true|false"
* `DD_LOG_LEVEL`
    - format: "ERROR|WARN|INFO|DEBUG"    
* `DD_TRACE_PROPAGATION_STYLE`
    - format: "datadog,tracecontext" 

### Features

| Feature                   | Working | Planned |
|---------------------------|---------|---------|
| Tracing                   | ✅      |         |
| Rule based sampling       | ✅      |         |
| Agent sampling            | ✅      |         |
| Tracecontext propagation  | ✅      |         |
| Remote config sampling rate| ❌      | ✅      |
| ASM SCA                   | ❌      | ✅      |
| Statsd metrics            | ❌      | ✅      |
| Continuous profiling      |         |         |
| DataJobs monitoring       |         |         |
| DataStreams monitoring    |         |         |
| Dynamic Instrumentation   |         |         |
| ASM WAF                   |         |         |

## Support

* MSRV: 1.84
* Opentelemetry version: 0.30

## Overview

This repository contains a collection of crates that work together to provide Datadog tracing capabilities for Rust applications, with full OpenTelemetry compatibility. The library allows you to instrument your Rust applications and send traces to Datadog while leveraging the OpenTelemetry ecosystem.

## Crates

### `dd-trace`
The core configuration and foundational types for Datadog tracing. This crate provides:
- **Configuration management**: Reads from environment variables and allows programmatic configuration
- **Core types**: Sampling decisions, priorities, and mechanisms
- **Constants**: Datadog-specific tag keys and values
- **Error handling**: Common error types used across the library
- **Logging**: Internal logging infrastructure

### `dd-trace-propagation`
Handles trace context propagation between services. This crate implements:
- **Datadog propagation format**: Extract and inject trace context using Datadog headers (`x-datadog-*`)
- **W3C Trace Context**: Support for W3C `traceparent` and `tracestate` headers
- **Composite propagator**: Automatically handles multiple propagation formats
- **Span context management**: Maintains trace IDs, span IDs, sampling decisions, and tags across service boundaries

### `dd-trace-sampling`
Implements Datadog's trace sampling logic. Features include:
- **Rule-based sampling**: Apply sampling rules based on service, operation name, resource, and tags
- **Rate limiting**: Control the maximum number of traces per second
- **Service-based sampling**: Apply different sampling rates per service/environment combination
- **Glob pattern matching**: Flexible matching rules for sampling decisions

### `datadog-opentelemetry-mappings`
Converts between OpenTelemetry and Datadog data models. This crate:
- **Span conversion**: Transforms OpenTelemetry spans to Datadog's span format
- **Semantic convention mapping**: Maps OpenTelemetry semantic conventions to Datadog equivalents
- **Attribute extraction**: Efficiently extracts and maps span attributes
- **Resource mapping**: Converts OpenTelemetry resources to Datadog service/env/version tags

### `datadog-opentelemetry`
The main integration point that brings everything together. This crate provides:
- **Span processor**: Collects spans and assembles them into traces before sending to Datadog
- **Span exporter**: Sends completed traces to the Datadog Agent
- **Trace registry**: Manages in-flight traces and ensures complete trace assembly
- **Propagator integration**: Integrates with OpenTelemetry's propagation system
- **Sampler integration**: Provides OpenTelemetry-compatible sampling

## How It All Works Together

The crates are orchestrated in `datadog-opentelemetry/src/lib.rs` through the `init_datadog` function:

1. **Configuration** (`dd-trace`): The system starts by loading configuration from environment variables and any programmatic overrides.

2. **Trace Registry** (`datadog-opentelemetry`): A shared registry is created to track all active traces in the application.

3. **Sampler** (`dd-trace-sampling`): A Datadog-compatible sampler is initialized with the configured sampling rules and rate limits.

4. **Propagator** (`dd-trace-propagation`): A composite propagator is created that can handle both Datadog and W3C trace context formats.

5. **Span Processor** (`datadog-opentelemetry`): The processor collects spans, uses the mappings to convert them to Datadog format, and manages trace assembly.

6. **Global Registration**: The tracer provider and propagator are registered with OpenTelemetry's global API.
