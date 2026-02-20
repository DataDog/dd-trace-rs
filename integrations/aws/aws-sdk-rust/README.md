# datadog-aws-sdk

Datadog trace context propagation for the [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust).

Automatically injects Datadog trace context into outgoing AWS SDK requests, enabling
distributed tracing across AWS services.

## Prerequisites

> **Required**: Your application must have a Datadog propagator registered via
> [`datadog-opentelemetry`](https://docs.rs/datadog-opentelemetry). The interceptor reads the
> current OpenTelemetry context and uses the globally configured propagator to extract trace
> headers.

## Getting Started

### 1. Add the dependency

```toml
[dependencies]
datadog-aws-sdk = "0.2"
```

### 2. Initialize Datadog tracing

Set up `datadog-opentelemetry` so a Datadog propagator is registered globally:

```rust
let _tracer_provider = datadog_opentelemetry::tracing().init();
```

### 3. Create your AWS client with the interceptor

```rust
use datadog_aws_sdk::DatadogInterceptor;
use aws_config::BehaviorVersion;

let sdk_config = aws_config::defaults(BehaviorVersion::latest())
    .load()
    .await;

let sqs_config = aws_sdk_sqs::config::Builder::from(&sdk_config)
    .interceptor(DatadogInterceptor::new())
    .build();

let sqs_client = aws_sdk_sqs::Client::from_conf(sqs_config);
```

### 4. Use the client as normal

Every operation on the client now automatically propagates Datadog trace context.
No per-call changes needed.

```rust
sqs_client
    .send_message()
    .queue_url("https://sqs.us-east-1.amazonaws.com/123456789/my-queue")
    .message_body("hello")
    .send()
    .await?;
```

## Supported Services

| Service | Status | Injection Point |
|---------|--------|-----------------|
| **SQS** | Supported | `_datadog` MessageAttribute (`DataType: String`, JSON-serialized trace headers) |
| **SNS** | Planned | `_datadog` MessageAttribute (`DataType: Binary`) — Binary avoids interfering with SNS subscription filter policies |
| **Kinesis** | Planned | TBD |
| **EventBridge** | Planned | `_datadog` key injected into the `Detail` JSON payload — EventBridge has no separate attributes mechanism |
