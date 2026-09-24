# Benchmarks

GitLab CI configuration for the benchmarks that run on the
[Benchmarking Platform](https://datadoghq.atlassian.net/wiki/spaces/APMINT/pages/2419261562/Benchmarking+Platform).

## Layout

- `rust-axum-realworld-parallel` stages: included in the root `.gitlab-ci.yml` from
  [apm-sdks-benchmarks](https://gitlab.ddbuild.io/DataDog/apm-reliability/apm-sdks-benchmarks)
  (`ci-rust-axum-realworld-parallel.yml`).
    - `FLAKY_BENCHMARKS_REGEX` for this suite lives there. Change it there.

## Marking a benchmark as flaky

The regex matches anywhere in the scenario name.

- `axum-realworld` quarantines every `axum-realworld` scenario.
- Anchor with `^...$` to target one scenario.

```yaml
FLAKY_BENCHMARKS_REGEX: "^webserver--axum-realworld--datadog--tracing--high_load$"
```

Open a ticket to fix or remove it. See
[Flaky Benchmarks Monitoring](https://datadoghq.atlassian.net/wiki/spaces/APMINT/pages/7223313012/Flaky+Benchmarks+Monitoring).
