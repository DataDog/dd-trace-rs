# datadog-aws-sdk

> Note: AI generated, will be revised.

Datadog trace context propagation for the [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust).

## Supported Services

| Service | Injection Point |
|---------|-----------------|
| SQS | `_datadog` MessageAttribute (`String`, JSON) |
| SNS | `_datadog` MessageAttribute (`Binary`, JSON bytes) |
| EventBridge | `_datadog` key in `Detail` JSON |

## Usage

Requires a Datadog propagator registered via [`datadog-opentelemetry`](https://docs.rs/datadog-opentelemetry).

```rust
use datadog_aws_sdk::DatadogInterceptor;

// Initialize Datadog tracing
let _tracer_provider = datadog_opentelemetry::tracing().init();

// Add the interceptor to any AWS service client
let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
    .interceptor(DatadogInterceptor::new())
    .build();
let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
```
