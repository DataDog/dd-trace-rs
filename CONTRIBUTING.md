# Contributing

Contributions are welcome. Pull requests for bug fixes are welcome, but before submitting new
features or changes to current functionality, please open an issue and discuss your ideas or propose
the changes you wish to make first. After a resolution is reached, a PR can be submitted for review.

## Repository Structure

See [docs/repo_structure.md](docs/repo_structure.md) for the full directory layout, module
overview, feature flags, and internal architecture.

## Configuration Options

See [docs/add_configurations.md](docs/add_configurations.md) for how to add new configuration
options.

## Rust Toolchain

- **MSRV**: 1.84.1 (set via `rust-version` in `Cargo.toml`)
- **Formatting**: pinned `nightly-2024-12-16` toolchain

Install the required toolchains and components:

```bash
rustup install nightly-2024-12-16
rustup component add rustfmt --toolchain nightly-2024-12-16
rustup component add clippy --toolchain nightly-2024-12-16
rustup install 1.84.1
rustup component add clippy --toolchain 1.84.1
```

## Formatting and Linting

### Rust formatting

Formatting uses `cargo fmt` with the pinned `nightly-2024-12-16` toolchain to ensure consistent
output across environments:

```bash
rustup run nightly-2024-12-16 cargo fmt -p <modified crate>
```

To check without modifying files (as CI does):

```bash
rustup run nightly-2024-12-16 cargo fmt --all -- --check
```

### Rust linting (clippy)

Clippy is run across every feature combination using `cargo-hack` v0.6.42:

```bash
cargo hack --each-feature clippy -- -D warnings
```

Install `cargo-hack` with:

```bash
cargo install cargo-hack@0.6.42
```

### Shell scripts (`*.sh`)

Shell scripts are linted with [shellcheck](https://www.shellcheck.net/) v0.11.0. To run locally:

```bash
find . -name '*.sh' -print0 | xargs -0 shellcheck
```

### Markdown files (`*.md`)

Markdown files are linted with [rumdl](https://github.com/rvben/rumdl) v0.1.25. To run locally:

```bash
rumdl check .
```

Install rumdl v0.1.25 with:

```bash
cargo install rumdl@0.1.25
```

### Pre-commit checklist

```bash
# Format code
rustup run nightly-2024-12-16 cargo fmt --all

# Lint Rust (all feature combinations)
cargo hack --each-feature clippy -- -D warnings

# Run tests
cargo nextest run --workspace --locked -E '!test(integration_tests::)'
cargo test --workspace --doc --locked

# Lint shell scripts and markdown
find . -name '*.sh' -print0 | xargs -0 shellcheck
rumdl check .

# Update licence file if dependencies changed
./scripts/generate-licenses.sh
```

## Code Style

- Prefer `impl Trait` over `Box<dyn Trait>` when possible
- Avoid code duplication as much as possible
- Document all public symbols
- Avoid `use` declarations (imports) inside functions. Place them at the top of the file, unless
  they are needed for tests only, in which case they should be placed at the top of the `mod tests`
  block.
- Keep functions simple and short (less than 100 lines).
- Keep indent level under 3 inside of functions, ideally under 2. Resort to early return / early
  break pattern rather than having complex logic inside of conditional blocks.

## Common Patterns

- Prefer `&str` over `String` in function parameters
- Use `Result<T, E>` for fallible operations, not panics
- Avoid possible panics like `unwrap` or `expect` in non-test code. If there's a reasonable
  default, consider `unwrap_or` / `unwrap_or_else`.
- Prefer `Arc::clone(x)` over `x.clone()` when `x` is an `Arc`
- Prefer `use` statements like `use std::sync::Arc` rather than fully qualifying types every time
  they are used (e.g. `std::sync::Arc`)
- Avoid eager combinators (`ok_or`, `unwrap_or`, `map_or`) when the fallback allocates or does
  meaningful work. Consider using `ok_or_else`, `unwrap_or_else`, or `map_or_else` instead.
- Avoid `#[allow(clippy::too_many_arguments)]`. Instead, try to simplify function signatures,
  introduce abstractions / structs, or as a last resort refactor to use a dedicated struct for
  parameters.
- Avoid adding dead code with `#[allow(clippy::dead_code)]`. Prefer deleting the code unless it
  will be used in subsequent work.
- Avoid shadowing names in the prelude, like `Result`, `None`, and `Iterator`. For instance, prefer
  `anyhow::Result<T>` instead of `use anyhow::Result`.
- Prefer iterator patterns instead of manual loops, where convenient. For instance, use `find`
  instead of a loop with an early `return`, and use `collect` instead of `.push` in a loop.

## Testing

- Bug fixes must include non-regression tests
- All functional changes require at least 1 test
- Tests are run with `cargo nextest run --workspace --locked -E '!test(integration_tests::)'`
- Doc-tests are run separately with `cargo test --workspace --doc --locked` (nextest does not
  support doc-tests)
- Integration tests (`integration_tests::` filter) require Docker — they spin up the
  `ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent` container automatically. Run them with
  `cargo nextest run --workspace --locked -E 'test(integration_tests::)'`. In CI they only execute
  on Linux.

## Working with Files

Always use git commands when adding, moving, or removing tracked files:

- **New file**: run `git add <file>` to stage it before writing content to it
- **Move/rename**: use `git mv <old> <new>` instead of `mv`
- **Delete**: use `git rm <file>` instead of `rm`

## Pull Requests

### Naming

All pull requests must follow the [Conventional Commits](https://www.conventionalcommits.org/)
specification. The PR title is linted automatically on every push. Format:

```text
type(scope): short description
```

Common types: `feat`, `fix`, `chore`, `refactor`, `docs`, `test`, `perf`, `ci`. Append `!` after
the type/scope for breaking changes (e.g. `chore(api)!: ...`). The scope is optional but
encouraged.

If referencing an internal ticket, place it at the end of the description inside `[]`, e.g.:

```text
feat(config): add visibility reporting [APMAPI-1693]
```

### Draft first

When opening a pull request, please open it as a draft to not auto-assign reviewers before the
pull request is in a reviewable state.

### AI generated code

If any code in the PR was contributed by an AI agent, apply the `ai generated` label to the PR.

## Third-party Licenses

When adding or updating dependencies, you must update the `LICENSE-3rdparty.csv` file to reflect
these changes. This file is checked by our CI pipeline to ensure all dependencies are properly
documented.

To update the license file:

1. Run `./scripts/generate-licenses.sh` (requires Docker)
2. Review the changes to `LICENSE-3rdparty.csv`
3. Commit the updated file

The script uses Docker to ensure the generated file matches our CI environment, avoiding
platform-specific differences. Otherwise the GH action will generate a correct
`LICENSE-3rdparty.csv` file artifact on failure, which you can download and add to your branch.

## Rust Code Review

When reviewing Rust code, pay attention to:

- **Error handling**: Proper use of `?` operator, meaningful error messages
- **Ownership**: Avoid unnecessary clones, prefer borrowing
- **Unsafe code**: Minimize and document all `unsafe` blocks
