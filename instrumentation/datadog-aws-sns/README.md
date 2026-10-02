# datadog-aws-sns

Datadog tracing for AWS SDK for Rust SNS operations.

## Supported operations

- Client spans for all SNS SDK operations.
- Trace-context propagation for `Publish` and `PublishBatch`.

## Setup and usage

See the crate documentation for setup instructions, usage examples, and API details.

## Limitations

Propagation uses message attributes and can be skipped when no attribute slot is available.
Leave room below the SNS message size limit for trace context, especially when propagating baggage.
