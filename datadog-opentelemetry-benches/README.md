# Datadog OpenTelemetry Benchmarks

This crate contains performance benchmarks for the `datadog-opentelemetry` crate.

## Benchmarks

### dd_otel_tracer_comparison

Compares the performance of Datadog tracing vs vanilla OpenTelemetry tracing using Axum web servers.

The benchmark tests various scenarios:
- Health endpoint calls
- Echo endpoint with request body processing
- Compute-intensive operations
- Nested span creation
- Middleware overhead
- Span creation overhead

## Running Benchmarks

To run all benchmarks:

```bash
cargo bench -p datadog-opentelemetry-benches
```

To run a specific benchmark:

```bash
cargo bench -p datadog-opentelemetry-benches --bench dd_otel_tracer_comparison
```

To run with additional criterion options:

```bash
cargo bench -p datadog-opentelemetry-benches --bench dd_otel_tracer_comparison -- --help
```

## Output

Benchmark results are generated in HTML format and can be found in:
`target/criterion/dd_otel_tracer_comparison/` 