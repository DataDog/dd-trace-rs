<!-- markdownlint-disable MD041 -->
[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![Documentation (master)][docs-master-badge]][docs-master-url]
[![Apache licensed][apache-badge]][apache-url]

[crates-badge]: https://img.shields.io/crates/v/datadog-opentelemetry.svg
[crates-url]: https://crates.io/crates/datadog-opentelemetry/
[docs-badge]: https://docs.rs/datadog-opentelemetry/badge.svg
[docs-url]: https://docs.rs/datadog-opentelemetry/
[docs-master-badge]: https://img.shields.io/badge/docs-master-blue
[docs-master-url]: https://tracing-rs.netlify.com/tracing_opentelemetry
[apache-badge]: https://img.shields.io/badge/license-Apache-blue.svg
[apache-url]: LICENSE


# dd-trace-rs

This library powers [Distributed Tracing](https://docs.datadoghq.com/tracing/), metrics and logging.
It provides OpenTelemetry API and SDK compatibility with Datadog-specific features and
optimizations.


## Usage

The `datadog-opentelemetry` crate provides an easy to use override for the rust
opentelemetry-sdk.

### Installation

Add to you Cargo.toml

```toml
datadog-opentelemetry = { version = "0.3.0" }
```

### Creating traces, metrics and logs

#### Tracing

To trace functions, you can either use the `opentelemetry` crate's
[API](https://docs.rs/opentelemetry/0.31.0/opentelemetry/trace/index.html) or the `tracing` crate
[API](https://docs.rs/tracing/0.1.44/tracing/) with the `tracing-opentelemetry`
[bridge](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/).

#### Metrics

To collect metrics, use the `opentelemetry` crate's
[Metrics API](https://docs.rs/opentelemetry/0.31.0/opentelemetry/metrics/index.html). For more
details, see the
[Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/dd_sdks/api_support/?platform=metrics&prog_lang=rust).

#### Logging

* Enable with the `logs` feature of this crate

To collect logs, you can use the [`log`](https://docs.rs/log/0.4.29/log/) crate with the
`opentelemetry_appender_log`. For more details, see the
[Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/dd_sdks/api_support/?platform=logs&prog_lang=rust).

### Library initialization

The following examples will read datadog and opentelemetry configuration from environment variables
and other available sources, initialize and set up the global providers for tracing, logging or
metrics

#### Tracing API

Requires

* [`tracing-subscriber`](https://docs.rs/tracing-subscriber/0.3.22/tracing_subscriber/)
* [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.32.1/tracing_opentelemetry/)
* [`tracing`](https://docs.rs/tracing/0.1.44/tracing/)

```rust ,no_run
use opentelemetry::trace::TracerProvider;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// This picks up env var configuration and other datadog configuration sources
let tracer_provider = datadog_opentelemetry::tracing().init();

tracing_subscriber::registry()
    .with(
        tracing_opentelemetry::layer()
            .with_tracer(tracer_provider.tracer("my_application_name")),
    )
    .init();

tracer_provider
    .shutdown_with_timeout(Duration::from_secs(1))
    .expect("tracer shutdown error");
```

#### Opentelemetry trace API

Requires

* [`opentelemetry`](https://docs.rs/opentelemetry/0.31.0/opentelemetry/) with the `trace` feature
  enabled

```rust ,no_run
use std::time::Duration;

// This picks up env var configuration and other datadog configuration sources
let tracer_provider = datadog_opentelemetry::tracing().init();

// Your code
// Now use standard OpenTelemetry APIs
use opentelemetry::global;
use opentelemetry::trace::Tracer;

let tracer = global::tracer("my-service");
let span = tracer.start("my-operation");
// ... do work ...

// Shutdown the tracer to flush the remaining data
tracer_provider
    .shutdown_with_timeout(Duration::from_secs(1))
    .expect("tracer shutdown error");
```

#### Opentelemetry metrics API

Requires

* the `metrics` feature of this crate to be enabled
* [`opentelemetry`](https://docs.rs/opentelemetry/0.31.0/opentelemetry/) with the `metrics` feature
  enabled
* [`tokio`](https://docs.rs/tokio)

The metrics provider MUST be initialized within a tokio context

```rust ,no_run
// Initialize metrics with default configuration
let meter_provider = datadog_opentelemetry::metrics().init();

// Use standard OpenTelemetry Metrics APIs
use opentelemetry::global;
use opentelemetry::metrics::Counter;
use opentelemetry::KeyValue;

let meter = global::meter("my-service");
let counter: Counter<u64> = meter.u64_counter("requests").build();
counter.add(1, &[KeyValue::new("method", "GET")]);

// Shutdown to flush remaining metrics
meter_provider.shutdown().unwrap();
```

#### Log API

Requires

* the `logs` feature of this crate to be enabled
* [`log`](https://docs.rs/log/0.4.29/log/)
* [`opentelemetry-appender-log`](https://docs.rs/opentelemetry-appender-log/0.31.0/opentelemetry_appender_log/)
* [`tokio`](https://docs.rs/tokio)

The logger provider MUST be initialized within a tokio context

```rust ,no_run
// Initialize logs with default configuration
let logger_provider = datadog_opentelemetry::logs().init();

let otel_log_appender = opentelemetry_appender_log::OpenTelemetryLogBridge::new(&logger_provider);
log::set_boxed_logger(Box::new(otel_log_appender)).unwrap();

// Before ending the program shutdown to flush remaining logs to the collector
logger_provider.shutdown();
```

For more details, see the
[Datadog OpenTelemetry Rust documentation](https://docs.datadoghq.com/opentelemetry/instrument/api_support/rust/).

### Configuration

Configuration can be passed either:

* Programmatically

```rust ,no_run
use datadog_opentelemetry::configuration::Config;
let config = Config::builder()
    .set_service("my_service".to_string())
    .set_env("prod".to_string())
    .build();

let tracer_provider = datadog_opentelemetry::tracing()
    .with_config(config.clone())
    // this also accepts options for the Opentelemetry SDK builder
    .with_max_attributes_per_span(64)
    .init();

let metrics_provider = datadog_opentelemetry::metrics()
    .with_config(config.clone())
    .init();

let logging_provider = datadog_opentelemetry::logs()
    .with_config(config.clone())
    .init();
```

For advanced usage and configuration information, check out [`DatadogTracingBuilder`],
[`configuration::ConfigBuilder`] and the
[library documentation](https://docs.rs/datadog-opentelemetry/0.3.0/datadog_opentelemetry/).

* Through env variables

```bash
DD_SERVICE=my_service DD_ENV=prod cargo run
```

Configuration of the OpenTelemetry SDK TracerProviderBuilder can be done when initializing the
library

```rust
#[derive(Debug)]
struct MySpanProcessor;
impl opentelemetry_sdk::trace::SpanProcessor for MySpanProcessor { ... }

// Custom otel tracer sdk options
datadog_opentelemetry::tracing()
    .with_max_attributes_per_span(64)
    // Custom span processor
    .with_span_processor(MySpanProcessor)
    .init();
```

## Support

* MSRV: 1.84

* [`opentelemetry`](https://docs.rs/opentelemetry/0.31.0/opentelemetry/) version: 0.31
* [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.32.1/tracing_opentelemetry/)
  version: 0.32
* [`opentelemetry-appender-log`](https://docs.rs/opentelemetry-appender-log/0.31.0/opentelemetry_appender_log/)
  version 0.31
* [`log`](https://docs.rs/log/0.4.29/log/) version 0.4

## Features

* `metrics` enabled the metrics provider
* `metrics-grpc` enabled the metrics provider, with GRPC OTLP export
* `metrics-http` enabled the metrics provider, with HTTP OTLP export
* `logs` enabled the log provider
* `logs-grpc` enabled the log provider, with GRPC OTLP export
* `logs-http` enabled the log provider, with HTTP OTLP export
