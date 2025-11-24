# Contributing

Contributions are welcomed
Pull requests for bug fixes are welcome, but before submitting new features or changes to current functionality, please open an issue and discuss your ideas or propose the changes you wish to make first. After a resolution is reached, a PR can be submitted for review.

## Pull request guidelines

### Naming

All pull requests must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. Our CI pipeline automatically checks PR titles and will fail if they don't conform to this format. Examples include

- `feat: add span processor for datadog exporter`
- `fix(sampling): correct rate limiting calculation`
- `chore: update dependencies to latest versions`
- `docs: add examples for custom span attributes`

### Draft first

When opening a pull request, please open it as a draft to not auto-assign reviewers before the pull request is in a reviewable state.

## Code Formatting and Linting

Before submitting a pull request, ensure your code passes all formatting and linting checks that run in our CI pipeline. This helps maintain code quality and consistency across the project.

### Prerequisites

The following tooling is needed

- Rust stable
- Rust nightly - for clippy and rustfmt
- Docker - for integration tests
- Python 3.14 - for running the config generation script

Make sure you have the required Rust toolchain installed:

```bash
# Install the specific nightly toolchain used for formatting
rustup install nightly-2024-12-16

# Install the minimum supported Rust version
rustup install 1.84

# Add required components
rustup component add rustfmt --toolchain nightly-2024-12-16
rustup component add clippy --toolchain nightly-2024-12-16
rustup component add clippy --toolchain 1.84
```

### Third-party Licenses

When adding or updating dependencies, you must update the `LICENSE-3rdparty.csv` file to reflect these changes. This file is checked by our CI pipeline to ensure all dependencies are properly documented.

To update the license file:

1. Run `./scripts/generate-licenses.sh` (requires Docker)
2. Review the changes to `LICENSE-3rdparty.csv`
3. Commit the updated file

The script uses Docker to ensure the generated file matches our CI environment, avoiding platform-specific differences.

Otherwise the GH action will generate a correct `LICENSE-3rdparty.csv` file artifact on failure, which you can download and add to your branch.

### Pre-commit Check

To run all the essential checks before committing:

```bash
# Format code
cargo +nightly-2024-12-16  fmt --all

# Run clippy on minimum supported version (most restrictive)
cargo +1.84 clippy --locked --workspace --all-targets -- -D warnings

# Build and test (including doc tests)
cargo test --workspace --locked --doc
cargo test --workspace --locked

# Check license compliance (if you've added/updated dependencies)
./scripts/generate-licenses.sh  # Updates LICENSE-3rdparty.csv
```
