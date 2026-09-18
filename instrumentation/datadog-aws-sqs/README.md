# datadog-aws-sqs

Datadog tracing for AWS SDK for Rust SQS operations.

## Supported operations

- Client spans for all SQS SDK operations.
- Trace-context propagation for `SendMessage` and `SendMessageBatch`.
- Producer trace links for `ReceiveMessage`, with `extract_context` available for consumer work.

## Setup and usage

See the crate documentation for setup instructions, usage examples, and API details.

## Limitations

Propagation uses message attributes and can be skipped when no attribute slot is available.
Leave room below the SQS message size limit for trace context, especially when propagating baggage.
