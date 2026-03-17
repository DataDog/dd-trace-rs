# datadog-aws-sdk

Datadog trace context propagation for the [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust).

## Supported Services

| Service | Injection Point |
|---------|-----------------|
| SQS | `_datadog` MessageAttribute (`String`, JSON) |
| SNS | `_datadog` MessageAttribute (`Binary`, JSON bytes) |
| EventBridge | `_datadog` key in `Detail` JSON |

## Usage

> **Pre-release:** This crate is not yet published to crates.io. Once published, replace the git dependency below with a versioned one (`datadog-aws-sdk = "0.x"`).

```toml
[dependencies]
datadog-aws-sdk = { git = "https://github.com/DataDog/dd-trace-rs", branch = "main" }
```

Requires a Datadog propagator registered via `datadog-opentelemetry`. Register the interceptor when building any AWS service client:

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

