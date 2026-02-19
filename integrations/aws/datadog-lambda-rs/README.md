# datadog-lambda-rs

Datadog Lambda tracing for Rust. Integrates with the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/) for trace context propagation and span management in AWS Lambda.

> **Note:** This POC targets **ARM (aarch64)** only. Build scripts use `cargo-zigbuild` to cross-compile for `aarch64-unknown-linux-gnu`.

## How it works

Currently uses **universal instrumentation** — the Datadog Lambda Extension handles root span creation, trace context extraction, and span forwarding. This crate provides:

- `wrap_handler` — wraps your Lambda handler to call the extension's `/start-invocation` and `/end-invocation` endpoints on each invoke, and flushes spans after completion
- `set_tracer_provider` — registers the `SdkTracerProvider` so pending spans are flushed at the end of each invocation
- `create_root_span` / `end_root_span` — lower-level API if you need manual control

Child spans created via `tracing` or the OpenTelemetry API are automatically parented to the root context provided by the extension.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
datadog-lambda-rs = "0.2"
datadog-opentelemetry = "0.2"
lambda_runtime = "0.13"
opentelemetry = "0.31"
tracing = "0.1"
tracing-opentelemetry = "0.32"
tracing-subscriber = { version = "0.3", features = ["json"] }
```

Register your tracer provider and wrap your handler:

```rust
// Register the provider so spans are flushed at the end of each invocation
set_tracer_provider(provider.clone());

// Wrap your handler to call extension lifecycle endpoints and flush spans
lambda_runtime::run(service_fn(wrap_handler(your_handler))).await
```

See the [examples](examples/) for full working Lambdas.

### Lambda environment variables

| Variable | Required | Description |
|---|---|---|
| `DD_API_KEY` | Yes | Datadog API key (read by the extension) |
| `DD_SERVICE` | Yes | Service name shown in Datadog |
| `DD_ENV` | Recommended | Environment tag (`dev`, `staging`, `prod`) |
| `DD_TRACE_ENABLED` | No | Set `true` to enable tracing (default: `true`) |

### Lambda layers

The Datadog Extension layer must be attached to the function:

| Layer | ARN format |
|---|---|
| Datadog Extension ARM | `arn:aws:lambda:<region>:464622532012:layer:Datadog-Extension-ARM:<version>` |

## How to run examples

Each example has a single `run.sh` script with subcommands: **`build`**, **`deploy`**, **`update`**, **`invoke`**.

### Prerequisites

- [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) installed
- AWS CLI configured with appropriate permissions
- A `DD_API_KEY` environment variable set
- An IAM role ARN with Lambda and SQS permissions

### Quick start

```bash
export DD_API_KEY="your-api-key"

# 1. Build
./scripts/examples/<example>/run.sh build

# 2. Deploy (creates queue, Lambdas, and SQS trigger)
./scripts/examples/<example>/run.sh deploy --role-arn arn:aws:iam::<account>:role/<role>

# 3. Invoke
./scripts/examples/<example>/run.sh invoke
```

> Run `./run.sh` with no arguments to see all available flags.

---

### SQS-Lambda

**Python producer → SQS → Rust consumer**

A Rust Lambda triggered by SQS that processes messages with child spans. A co-located Python Lambda acts as the producer.

| | Path |
|---|---|
| Rust source | [`examples/SQS-Lambda/sqs_lambda.rs`](examples/SQS-Lambda/sqs_lambda.rs) |
| Script | [`scripts/examples/SQS-Lambda/run.sh`](scripts/examples/SQS-Lambda/run.sh) |

---

### Rust-SQS-Producer

**Rust producer → SQS → Python consumer**

A Rust Lambda that sends messages to SQS with trace context injected via [`datadog-aws-sdk`](../aws-sdk-rust/)'s `DatadogInterceptor`. A downstream Python Lambda (auto-instrumented by ddtrace) consumes the queue, producing a connected trace.

```
rust-sqs-producer
  └─ SQS.SendMessage
      └─ python-sqs-consumer
```

| | Path |
|---|---|
| Rust source | [`examples/Rust-SQS-Producer/rust_sqs_producer.rs`](examples/Rust-SQS-Producer/rust_sqs_producer.rs) |
| Script | [`scripts/examples/Rust-SQS-Producer/run.sh`](scripts/examples/Rust-SQS-Producer/run.sh) |

## What's working

- Extension integration (`start-invocation` / `end-invocation`)
- `wrap_handler` automatic lifecycle management
- Span flush on each invocation via `set_tracer_provider`
- End-to-end trace propagation: Rust Lambda → SQS → Python Lambda (via `datadog-aws-sdk`)

## Roadmap

### Local span creation (extensionless)

Replace extension-delegated root spans with locally created spans. The extension is only needed for trace export — span management will be fully local.

- `create_function_span` — function execution span with Lambda metadata tags (cold_start, function_arn, request_id, etc.)
- `create_root_span` (local) — create root span without calling the extension
- `create_cold_start_span` — emit cold-start spans
- `extract_synthetic_context` / `create_synthetic_spans` — parse and convert upstream service spans from event payloads
- `parse_arn` — strip version/alias suffix from ARN for resource name tags

### Configuration

- Config struct + builder with env var fallback (`DD_TRACE_ENABLED`, `DD_ENHANCED_METRICS`, `DD_LOG_LEVEL`)

### Metrics

- DogStatsD client (UDP to `127.0.0.1:8125`)
- Custom metrics API
- Enhanced metrics (`aws.lambda.enhanced.*`)
