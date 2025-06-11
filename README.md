# dd-trace-rs

`dd-trace-rs` is a Rust library for tracing and monitoring applications using Datadog.

# State of the repository

This is still in ‼️*PREVIEW*‼️, use at your own risks

# Contributing

## Third-party Licenses

When adding or updating dependencies, you must update the `LICENSE-3rdparty.csv` file to reflect these changes. This file is checked by our CI pipeline to ensure all dependencies are properly documented.

To update the license file:

1. Run `./scripts/generate-licenses.sh` (requires Docker)
2. Review the changes to `LICENSE-3rdparty.csv`
3. Commit the updated file

The script uses Docker to ensure the generated file matches our CI environment, avoiding platform-specific differences.
