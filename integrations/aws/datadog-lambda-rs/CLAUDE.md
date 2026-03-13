# datadog-lambda-rs

Datadog Lambda tracing for Rust. Wraps Lambda handlers to extract trace context from event
payloads, create inferred spans for upstream managed services, and instrument the invocation
with an `aws.lambda` root span.

## MSRV

1.85.0 (not the repo-wide 1.84.1).

## Architecture

```
src/
  lib.rs               public API: Config, wrap_handler, DatadogLambdaLayer
  invocation.rs        LambdaSpan, InvocationScope, start/run lifecycle, create_root_span
  span_inferrer/
    mod.rs             SpanInferrer (payload -> OTel parent context pipeline)
    carrier.rs         carrier key constants, validation
    triggers/
      mod.rs           Trigger enum dispatch
      sqs.rs           SQS extraction (+ nested SNS/EB detection)
      sns.rs           SNS extraction (+ nested EB detection)
      eventbridge.rs   EventBridge extraction
```

Each module has a single responsibility:
- `lib.rs` — what consumers call
- `invocation.rs` — one Lambda invocation, start to finish
- `span_inferrer/` — "what happened before this Lambda was invoked?"

## Invariants

- Tracing must never break the customer's Lambda invocation. Errors are silent no-ops.
- OTel-only. Do not add `tracing-opentelemetry` or re-introduce the Smithy span bridge.
- Import constants from `datadog_opentelemetry::propagation::datadog` and
  `datadog_opentelemetry::constants`. Do not duplicate string literals.
- Design for scalability: functional code is not enough — it must be the correct, most
  maintainable design. Adding a new trigger should only require changes in
  `span_inferrer/triggers/` (new file + enum variant). If a change touches unrelated modules,
  reconsider the design.

## Code Style

Follow repo-wide CONTRIBUTING.md.

- No `unwrap`/`expect` in non-test code.
- No dead code. If a field has no consumer, do not add it.
- Use `tracing::debug!`, `tracing::warn!`, `tracing::error!` with structured fields.
- Comments only when the code does not speak for itself.

## Span Attributes

Root span (`aws.lambda`): `operation_name` (`"aws.lambda"`), `language` (`"rust"`),
`resource.name`, `span.type` (`"serverless"`), `request_id`, `cold_start` (bool),
`async_invocation` (bool), `function_arn`, `function_version`, `functionname`,
`resource_names`, `_dd.origin` (`"lambda"`).
On error: `error` (bool), `error.message`.

Inferred spans: `service.name`, `resource.name`, `span.type`, `operation_name`,
`peer.service`, plus trigger-specific tags.

## Testing

```bash
cargo test -p datadog-lambda-rs --locked
rustup run nightly-2024-12-16 cargo fmt -p datadog-lambda-rs
cargo clippy -p datadog-lambda-rs -- -D warnings
```

All functional changes require at least one test. Fixtures in `tests/payloads/`.

## Standard of Review

Before writing any code: would a staff engineer approve this? Be ready to justify decisions
and present alternatives. Simplest correct solution wins. Flag smells before they reach review.

## Commit Messages

Conventional Commits, concise.

```
feat(lambda): add error.message to root span on handler error
fix(lambda): continue to next header location on non-object value
```

Apply the `ai generated` label to any PR with AI-generated code.
