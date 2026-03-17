# datadog-lambda-rs

Datadog Lambda tracing for Rust.

## Usage

```toml
[dependencies]
datadog-lambda-rs = { git = "https://github.com/DataDog/dd-trace-rs", branch = "david.ogbureke/lambda-integration" }
datadog-aws-sdk = { git = "https://github.com/DataDog/dd-trace-rs", branch = "david.ogbureke/lambda-integration" }
datadog-opentelemetry = { git = "https://github.com/DataDog/dd-trace-rs", branch = "david.ogbureke/lambda-integration" }
lambda_runtime = "0.13"
```

Wrap your handler to instrument the Lambda invocation:

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

To propagate trace context into outbound AWS calls, add `DatadogAwsInterceptor` to your service client:

```rust
use aws_config::BehaviorVersion;
use aws_sdk_sqs::Client as SqsClient;
use datadog_aws_sdk::DatadogAwsInterceptor;

let sdk_config = aws_config::defaults(BehaviorVersion::latest()).load().await;
let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
    .interceptor(DatadogAwsInterceptor::new())
    .build();
let client = SqsClient::from_conf(sqs_config);
```

## Configuration

| Variable | Description |
|---|---|
| `DD_SERVICE` | Service name |
| `DD_ENV` | Environment tag |
| `DD_API_KEY` | Datadog API key |
