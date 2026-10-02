# datadog-aws-lambda

Datadog tracing for AWS Lambda handlers using `lambda_runtime`.

## What it instruments

- Lambda invocations handled by the wrapped Tower service.
- Handler failures and event deserialization failures.
- Invocation context for child spans created by the handler and instrumented AWS clients.

## Setup and usage

See the crate documentation for setup instructions, usage examples, and API details.

## Limitations

The wrapper initializes the tracer provider itself. It disables client-side trace
statistics and uses synchronous trace writes to accommodate Lambda runtime freezes,
including when custom configuration is supplied.
