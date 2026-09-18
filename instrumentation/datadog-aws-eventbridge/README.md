# datadog-aws-eventbridge

Datadog tracing for AWS SDK for Rust EventBridge operations.

## Supported operations

- Client spans for all EventBridge SDK operations.
- Trace-context propagation for `PutEvents`.

## Setup and usage

See the crate documentation for setup instructions, usage examples, and API details.

## Limitations

Propagation requires each event's `detail` to be a JSON object; unsupported payloads are
sent without injected context. Leave room below the EventBridge `PutEvents` size limit
for trace context, especially when propagating baggage.
