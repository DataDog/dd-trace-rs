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
datadog-opentelemetry = { version = "0.5.3" }
```

### Creating traces, metrics and logs

#### Tracing

To trace functions, you can either use the `opentelemetry` crate's
[API](https://docs.rs/opentelemetry/0.33.0/opentelemetry/trace/index.html) or the `tracing` crate
[API](https://docs.rs/tracing/0.1.44/tracing/) with the `tracing-opentelemetry`
[bridge](https://docs.rs/tracing-opentelemetry/latest/tracing_opentelemetry/).

#### Metrics

To collect metrics, use the `opentelemetry` crate's
[Metrics API](https://docs.rs/opentelemetry/0.33.0/opentelemetry/metrics/index.html). For more
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
* [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.34.0/tracing_opentelemetry/)
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

* [`opentelemetry`](https://docs.rs/opentelemetry/0.33.0/opentelemetry/) with the `trace` feature
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
* [`opentelemetry`](https://docs.rs/opentelemetry/0.33.0/opentelemetry/) with the `metrics` feature
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
* [`opentelemetry-appender-log`](https://docs.rs/opentelemetry-appender-log/0.33.0/opentelemetry_appender_log/)
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

### Overriding the sampling decisions

Whenever a new trace is started, the sampler decides whether this trace will be sent to the
intake or not. This is called a sampling decision.
This sampling decision is usually immutable from there and applies to all spans in the trace.

Using the [`datadog_telemetry_api::set_sampling_decision`] API it is possible to override
sampling decisions while the span is active, usually because some rare or unexpected event
has happened and you want to be sure to record and send it to storage.

The sampling decision set for the trace takes effect immediately, and all active spans
belonging to the same trace will inherit it, even if they were started before the call.

The global `set_sampling_decision` method is callable from anywhere, as long as an instance
of [`DatadogTelemetry`] has been installed, either with [`DatadogTracingBuilder::init()`],
or by calling [`datadog_telemetry_api::set_global`].

#### Limitations

Setting [`datadog_telemetry_api::SamplingDecision::Keep`] does not guarantee that all spans
of the trace will be sampled: only the currently active spans, and the spans started after
the call, are guaranteed. Spans closed before the call might carry the original sampling
decision.

`set_sampling_decision` should be called only with spans started by an
[`opentelemetry_sdk::trace::SdkTracerProvider`] installed by the same
[`DatadogTracingBuilder::init()`] call, or returned by the same
[`DatadogTracingBuilder::init_local()`] call.

* Global API

```rust ,no_run
use opentelemetry::global;
use opentelemetry::trace::{TraceContextExt, Tracer};

global::tracer("my-service").in_span("my-operation", |cx| {
    datadog_telemetry_api::set_sampling_decision(
        cx.span().span_context().clone(),
        datadog_telemetry_api::SamplingDecision::Keep,
    );
});
```

* Local API

```rust ,no_run
use datadog_telemetry_api::DatadogTelemetryApi;
use opentelemetry::trace::{TraceContextExt, Tracer, TracerProvider};

let datadog_opentelemetry::TracingComponents {
    tracer_provider,
    datadog_telemetry,
    ..
} = datadog_opentelemetry::tracing().init_local();

tracer_provider.tracer("my-service").in_span("my-operation", |cx| {
    datadog_telemetry.set_sampling_decision(
        cx.span().span_context().clone(),
        datadog_telemetry_api::SamplingDecision::Keep,
    );
});
```

### Thread context sharing

This tracer supports sharing the active context with an external
(out-of-process) reader, typically the Full Host Profiler, correlating CPU
profiles with spans. The implementation follows the [OTel
specification][otep-4947], making the context visible to other compatible eBPF
profilers or any OTel-compliant external reader.

The thread-level context sharing is **Linux-only**, as per the current
standard.

To enable thread-level context sharing on Linux:

1. Enable the `otel-thread-ctx` feature on your `datadog-opentelemetry` dependency.
2. Depending on the type of your crate:

   * If you're building an executable, add `datadog-opentelemetry` to your
     `[build-dependencies]` as well (do not enable the `otel-thread-ctx`
     feature for the build dependency):

     ```toml
     [build-dependencies]
     datadog-opentelemetry = { version = "0.5.3" }
     ```

     Finally, add the following line to your `build.rs` main function (create one
     if needed):

     ```rust
     datadog_opentelemetry::build::emit_otel_thread_ctx_build_instructions();
     ```

   * If you're building a Rust library (`(r)lib`), you'll have to ensure the
     instructions above are applied to _every downstream executable that uses
     your library_.
   * If you're building a shared dynamic library (`(c)dylib`), please note that
     **while the following instructions should work in most environments,
     building a dynamic library with thread context support is currently
     experimental at best**. In particular, a crate with both a binary target
     and a (c)dylib target won't compile with the instructions below.

     Add `datadog-opentelemetry` to your `[build-dependencies]` as well (do not
     enable the `otel-thread-ctx` feature for the build dependency):

     ```toml
     [build-dependencies]
     datadog-opentelemetry = { version = "0.5.3" }
     ```

     Finally, add the following line to your `build.rs` main function (create one
     if needed):

     ```rust
     datadog_opentelemetry::build::emit_otel_thread_ctx_dylib_build_instructions();
     ```

We are working on lifting the need for a custom build script in the future.

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
[library documentation](https://docs.rs/datadog-opentelemetry/0.5.3/datadog_opentelemetry/).

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

### Tracer diagnostics

The tracer reports on itself - configuration problems, transport failures, dropped spans. Where
those diagnostics go depends on the application: if it has installed a `tracing` subscriber, they
are emitted to it under the target `datadog_opentelemetry`; if it has not, they are printed to
stdout and stderr, so a bare binary still sees them.

With a subscriber installed, two independent settings apply, and a diagnostic has to pass **both**:

| Setting | Decides | Default |
| --- | --- | --- |
| `DD_LOG_LEVEL`, or `ConfigBuilder::set_log_level_filter` | how verbose the tracer is: which diagnostics it produces at all | `ERROR` |
| the subscriber's own filter, typically `RUST_LOG` | which of those it keeps, and where they go | `ERROR`, for `EnvFilter` with `RUST_LOG` unset |

Neither overrides the other: the more restrictive of the two wins, so raising one alone leaves the
other in force. Both have to be raised to see anything below `ERROR`.

```bash
# Errors only: the tracer produces nothing below ERROR for the filter to admit.
RUST_LOG=datadog_opentelemetry=debug cargo run

# Errors only: the tracer produces DEBUG diagnostics, and the subscriber discards them.
DD_LOG_LEVEL=debug RUST_LOG=error cargo run

# DEBUG diagnostics reach the subscriber, which decides where they end up.
DD_LOG_LEVEL=debug RUST_LOG=datadog_opentelemetry=debug cargo run
```

## Support

* MSRV: 1.91.1
* [`opentelemetry`](https://docs.rs/opentelemetry/0.33.0/opentelemetry/) version: 0.33
* [`tracing-opentelemetry`](https://docs.rs/tracing-opentelemetry/0.34.0/tracing_opentelemetry/)
  version: 0.34
* [`opentelemetry-appender-log`](https://docs.rs/opentelemetry-appender-log/0.33.0/opentelemetry_appender_log/)
  version 0.33
* [`log`](https://docs.rs/log/0.4.29/log/) version 0.4

## Features

* `metrics` enabled the metrics provider
* `metrics-grpc` enabled the metrics provider, with GRPC OTLP export
* `metrics-http` enabled the metrics provider, with HTTP OTLP export
* `logs` enabled the log provider
* `logs-grpc` enabled the log provider, with GRPC OTLP export
* `logs-http` enabled the log provider, with HTTP OTLP export
* `log-compat` routes the tracer's internal diagnostics through the `log` facade when no `tracing`
  subscriber is available
* `otel-thread-ctx` enables [sharing contexts with external readers][otep-4947] (typically
  an eBPF profiler). Executables additionally require a `build.rs` calling the build helper:
  see the dedicated section above.

[otep-4947]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4947-thread-ctx.md
