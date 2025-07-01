# Contributing

## Code Formatting and Linting

Before submitting a pull request, ensure your code passes all formatting and linting checks that run in our CI pipeline. This helps maintain code quality and consistency across the project.

### Prerequisites

Make sure you have the required Rust toolchain installed:

```bash
# Install the specific nightly toolchain used for formatting
rustup install nightly-2024-12-16

# Install the minimum supported Rust version
rustup install 1.81.0

# Add required components
rustup component add rustfmt --toolchain nightly-2024-12-16
rustup component add clippy --toolchain nightly-2024-12-16
rustup component add clippy --toolchain 1.81.0
```

### Running Format Checks Locally

#### Rust Formatting (rustfmt)

Our project uses rustfmt with a custom configuration defined in `rustfmt.toml`. To check and fix formatting:

```bash
# Check if code is properly formatted (same as CI)
rustup run nightly-2024-12-16 cargo fmt --all -- --check

# Automatically fix formatting issues
rustup run nightly-2024-12-16 cargo fmt --all
```

#### Linting (clippy)

We run clippy with strict settings that treat all warnings as errors. Test your code against multiple Rust versions:

```bash
# Check with minimum supported Rust version (1.81.0)
rustup run 1.81.0 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Check with stable Rust
cargo +stable clippy --locked --workspace --all-targets --all-features -- -D warnings -Aunknown-lints -Ainvalid_reference_casting -Aclippy::redundant-closure-call

# Check with nightly (matches CI exactly)
rustup run nightly-2024-12-16 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -Aunknown-lints -Ainvalid_reference_casting -Aclippy::redundant-closure-call
```

### Quick Pre-commit Check

To run all the essential checks before committing:

```bash
# Format code
rustup run nightly-2024-12-16 cargo fmt --all

# Run clippy with the minimum supported version
rustup run 1.81.0 cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

# Build and test
cargo build --workspace --locked
cargo test --workspace --locked
```

## Third-party Licenses

When adding or updating dependencies, you must update the `LICENSE-3rdparty.csv` file to reflect these changes. This file is checked by our CI pipeline to ensure all dependencies are properly documented.

To update the license file:

1. Run `./scripts/generate-licenses.sh` (requires Docker)
2. Review the changes to `LICENSE-3rdparty.csv`
3. Commit the updated file

The script uses Docker to ensure the generated file matches our CI environment, avoiding platform-specific differences.
