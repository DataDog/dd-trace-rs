# Rust Instrumentation

This directory contains Rust instrumentations that are maintained
separately from the core OpenTelemetry SDK. Add code here when instrumentation
depends on a framework, runtime, client library, or protocol-specific API that
does not belong in the SDK crate itself.

## Adding Instrumentation

Before adding instrumentation, be clear about:

- The library, runtime, or protocol boundary it covers.
- The crate name, using `datadog-*` for public instrumentation crates.
- How users enable it.
- The spans, attributes, and propagation behavior it adds.
- The supported dependency versions.

Prefer opt-in APIs such as middleware, layers, interceptors, service wrappers,
or builder extensions. Avoid depending on unstable or incidental behavior of
the instrumented dependency.

Public crates should contain user-facing instrumentation APIs and rustdocs.
Each publishable instrumentation crate should document what it instruments,
how to enable it, and any propagation or compatibility limits. Keep shared
implementation details private when they are only needed inside this workspace.
Reusable test support should live in a private `*-test-utils` crate rather than
in a published instrumentation crate.

## Behavior

Instrumentation should preserve application behavior. When tracing work cannot
be done safely, skip it and let the original operation continue.

Keep overhead visible in code review, especially around parsing, cloning,
allocation, and payload rewriting. Avoid panics in production code.

Span and attribute names should be stable enough for tests, dashboards, and
documentation. Propagation should use documented metadata fields and treat
invalid context as missing context.

## Versioning

Instrumentation crates can have independent versions and release cycles. Version
bumps should reflect changes in the instrumentation API, telemetry contract, or
supported dependency versions for that crate, without forcing unrelated
instrumentation crates to release at the same time.

Keep dependency compatibility explicit in `Cargo.toml` and release notes. Use
workspace-level dependencies for shared infrastructure and dependency versions
that should intentionally move together across this workspace. Keep
instrumented dependency versions in the affected crate when they are part of
that crate's compatibility contract.

When an instrumented dependency needs a breaking compatibility update, prefer a
new major version for the affected instrumentation crate.

## Tests

Prefer focused tests for:

- Span creation, attributes, and parent context selection.
- Error and status reporting.
- Context injection, extraction, and skipped propagation.
- Preservation of the original operation result.

Functional changes and bug fixes require regression coverage.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the canonical test commands.

## Third-party Licenses

When adding or updating dependencies in this workspace, update
`LICENSE-3rdparty.csv` before opening a pull request. The repository-level
license script generates CSV files for both the root workspace and this
workspace:

```bash
../scripts/update_license_3rdparty.sh
```

Review the generated changes to `LICENSE-3rdparty.csv`. The script uses the
pinned local license tool when it is available, or can run through Docker when
needed. If CI generates a corrected license CSV artifact, download that artifact
and add it to the branch.

## Local Development

Follow the repository-level setup, formatting, linting, testing, and pull
request guidance in [CONTRIBUTING.md](../CONTRIBUTING.md). Run workspace-scoped Cargo commands
from this directory when working only on instrumentation code.

This workspace declares **Rust 1.91.1** as its **MSRV** in `Cargo.toml`, which is
**newer** than the repository root MSRV. Install it in addition to the
repository-level toolchains:

```bash
rustup install 1.91.1
rustup component add clippy --toolchain 1.91.1
```

To make Cargo use the instrumentation MSRV by default in this directory, set a
local rustup override:

```bash
rustup override set 1.91.1
```
