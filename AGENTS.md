# Agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) before starting any work. It contains all guidelines for
repository structure, toolchain setup, formatting and linting, code style, testing, working with
files, and pull request requirements.

## Adding or Changing a Configuration

Adding, renaming, deprecating, or changing a configuration option (a `DD_*` or `OTEL_*` environment
variable) MUST follow [docs/add_configurations.md](docs/add_configurations.md). Do not read
configuration environment variables directly with `std::env::var` or skip any of these steps:

- Declare the option in `supported-configurations.json`, keeping the keys sorted. Renames and
  deprecations go through `aliases` and `deprecated` as described in the guide. Set
  `"sensitive": true` for secrets so their values are excluded from configuration telemetry.
- Regenerate `datadog-opentelemetry/src/core/configuration/supported_configurations.rs` with
  `python3 scripts/local_config_map_generate.py`; never edit it by hand. The
  `Check Configuration Files` GitHub workflow fails if the keys are unsorted or the generated
  file is out of date.
- The key and its `version` must exist in the central configuration registry, otherwise the
  `validate_supported_configurations_v2_local_file` GitLab CI job fails.
- Read the value through `SupportedConfigurations` in
  `datadog-opentelemetry/src/core/configuration/configuration.rs` and add tests for it.
