# datadog-aws-lambda

Datadog tracing for AWS Lambda handlers using `lambda_runtime`.

## What it instruments

- Lambda invocations handled by the wrapped Tower service.
- Inferred parent spans for API Gateway REST, HTTP and WebSocket APIs, Lambda Function URLs,
  SQS, SNS, EventBridge, Kinesis, DynamoDB, S3, and MSK events.
- Trace context from event headers and message carriers, including SNS and EventBridge events
  wrapped in SQS, and EventBridge events wrapped in SNS.
- Propagation from ALB events and deterministic Step Functions context, without an inferred span.
- Handler failures and event deserialization failures.
- Invocation context for child spans created by the handler and instrumented AWS clients.

## Setup and usage

See the crate documentation for setup instructions, usage examples, and API details.

## Limitations

The wrapper initializes the tracer provider itself. It disables client-side trace
statistics and uses synchronous trace writes to accommodate Lambda runtime freezes,
including when custom configuration is supplied.

## Event inference

The internal `inference` module is ported from
[Bottlecap's invocation triggers](https://github.com/DataDog/datadog-lambda-extension/tree/55057d909ac60dc7ebf9f8fd04f10da7e4902119/bottlecap/src/lifecycle/invocation/triggers).
The trigger parsers and their fixture tests live in this crate; building the Lambda integration no
longer requires the experimental `libdd-trace-inferrer` Git branch.

The port replaces Bottlecap's protobuf span with the fields needed by the OpenTelemetry adapter. It
retains event matching, service resolution, metadata, timestamps, carrier extraction, wrapped
trigger detection, Step Functions IDs, and SQS AWS trace header fallback. Explicit carrier context
is preferred over generated context. Datadog and W3C carriers use the tracer's configured
propagator. Extension-only DSM checkpoints, span pointers, and AppSec processing are outside this
module.

Async inferred spans end at invocation start; synchronous spans end at invocation completion.
A wrapped outer span ends when the inner event starts. The handler's `aws.lambda` span is a child
of the innermost inferred span, continuing the upstream trace when context is available.
