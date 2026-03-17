# datadog-lambda-rs

Datadog Lambda tracing for Rust.

## Usage

```toml
[dependencies]
datadog-lambda-rs = "0.3"
datadog-opentelemetry = "0.3"
lambda_runtime = "0.13"
```

```rust
use datadog_lambda_rs::wrap_handler;
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
                .set_trace_writer_synchronous_write(true) // required for Lambda
                .build(),
        )
        .init();
    lambda_runtime::run(service_fn(wrap_handler(handler, provider))).await
}
```

## Configuration

| Variable | Description |
|---|---|
| `DD_SERVICE` | Service name |
| `DD_ENV` | Environment tag |
| `DD_API_KEY` | Datadog API key |
