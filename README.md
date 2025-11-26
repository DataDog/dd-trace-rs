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

This library powers [Distributed Tracing](https://docs.datadoghq.com/tracing/). It provides OpenTelemetry API and SDK compatibility with Datadog-specific features and optimizations.

## Usage

The `datadog-opentelemetry` crate provides an easy to use override for the rust opentelemetry-sdk.

### Installation

Add to you Cargo.toml

```toml
datadog-opentelemetry = { version = "0.1.0" }
```

### Tracing

To trace functions, you can either use the `opentelemetry` crate's [API](https://docs.rs/opentelemetry/0.31.0/opentelemetry/trace/index.html) or the `tracing` crate [API](https://docs.rs/tracing/0.1.41/tracing/) with the `tracing-opentelemetry` [bridge](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/).

### Initialization

The following examples will read datadog and opentelemetry configuration from environment variables and other
available sources, initialize and set up the tracer provider and the text distributed tracing propagators globally.

#### Tracing API

* Requires `tracing-subscriber` and `tracing`

```rust
use opentelemetry::trace::TracerProvider;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // This picks up env var configuration and other datadog configuration sources
    let tracer_provider = datadog_opentelemetry::tracing()
        .init();

    tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("my_application_name")))
        .init();

    tracer_provider.shutdown_with_timeout(Duration::from_secs(1)).expect("tracer shutdown error");
}
```

#### Opentelemetry API

* requires `opentelemetry`

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

### Configuration

Configuration can be passed either:

* Programmatically

```rust
let config = datadog_opentelemetry::configuration::Config::builder()
    .set_service("my_service".to_string())
    .set_env("prod".to_string())
    .build();
let tracer_provider = datadog_opentelemetry::tracing()
        .with_config(config)
        // this also accepts options for the Opentelemetry SDK builder
        .with_max_attributes_per_span(64)
        .init();
```

For advanced usage and configuration information, check out the [library documentation](https://docs.rs/datadog-opentelemetry/0.1.0/datadog_opentelemetry/).

* Through env variables

```bash
DD_SERVICE=my_service DD_ENV=prod cargo run
```

This API call also be used to pass options to the OpenTelemetry SDK TracerProviderBuilder

```rust
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
* [opentelemetry](https://docs.rs/opentelemetry/0.31.0/opentelemetry/) version: 0.31
* [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.32.0/tracing_opentelemetry/) version: 0.32
