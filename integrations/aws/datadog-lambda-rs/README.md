# datadog-lambda-rs

Datadog Lambda tracing for Rust. Requires the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/) deployed as a Lambda layer.

## Usage

Add the dependencies to your `Cargo.toml`:

```toml
[dependencies]
datadog-lambda-rs = "0.2"
datadog-opentelemetry = "0.2"
lambda_runtime = "0.13"
```

Wrap your handler with `wrap_handler` and initialize the tracer provider:

```rust
use datadog_lambda_rs::{set_tracer_provider, wrap_handler};
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::Value;

async fn handler(event: LambdaEvent<Value>) -> Result<Value, Error> {
    Ok(Value::Null)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = datadog_opentelemetry::tracing()
        .with_config(
            datadog_opentelemetry::configuration::Config::builder()
                .set_service("my-service".to_string())
                .set_env("dev".to_string())
                .set_version("1.0.0".to_string())
                .build(),
        )
        .init();
    set_tracer_provider(provider);
    lambda_runtime::run(service_fn(wrap_handler(handler))).await
}
```

## Configuration

Set these as Lambda environment variables:

| Variable | Required | Description |
|---|---|---|
| `DD_API_KEY` | Yes | Datadog API key (read by the extension) |
| `DD_SERVICE` | Yes | Service name |
| `DD_ENV` | Recommended | Environment tag |

## Examples

End-to-end examples covering SQS, SNS, and EventBridge with Rust and Python Lambdas, deployed via CDK.

```
examples/
├── sqs/          Rust ↔ Python via SQS
├── sns/          Rust ↔ Python via SNS
└── eventbridge/  Rust ↔ Python via EventBridge
```

Each directory contains `main.rs` (Rust) and `handler.py` (Python) with a `rust-producer/` and `rust-consumer/` pair.

```bash
./scripts/build-examples.sh        # cross-compile Rust examples
cd cdk && npx cdk deploy           # deploy all 12 Lambdas + transports
```
