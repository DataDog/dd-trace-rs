# dd-trace-rs Support Policy

This document defines what Datadog supports in `dd-trace-rs` (the `datadog-opentelemetry` crate and
its companion crates): which Rust toolchains, OpenTelemetry versions, operating systems, and
architectures are covered, how long a given release is supported, and how versioning, deprecation,
and security fixes are handled.

It is the authoritative reference for customers and for the maintaining team. It is the Rust
instantiation of Datadog's broader APM library support model and is designed to stay compatible with
the [Datadog Agent supported platforms](https://docs.datadoghq.com/agent/supported_platforms/) and
the APM runtime-version-support policy.

> Maintainers: when any value in this document changes (MSRV, OpenTelemetry version, a tier change,
> a lifecycle date), update this file in the same change set and keep the README `## Support`
> section and the public compatibility docs in sync.

## What "support" means

A release or platform that is **supported** entitles you to:

- **Fixes** — bug fixes and, where applicable, security fixes, delivered according to the lifecycle
  and security sections below.
- **Assistance** — help through [Datadog Support](https://www.datadoghq.com/support/) and via
  [GitHub issues](https://github.com/DataDog/dd-trace-rs/issues), within the scope of this policy.
- **Compatibility guarantees** — the stability and SemVer guarantees described under
  [Versioning and compatibility](#versioning-and-compatibility).

Anything outside this policy (an EOL release, a Tier 3 platform, an unstable API, an unlisted
OpenTelemetry version) is **best-effort**: it may work, but Datadog makes no commitment to fix it.

## Support tiers

dd-trace-rs uses the following tiers, consistent with other Datadog APM libraries:

| Tier            | Features      | Bug fixes        | Security fixes   | Notes                                      |
| --------------- | ------------- | ---------------- | ---------------- | ------------------------------------------ |
| **Preview**     | Yes           | Best-effort      | Best-effort      | Early access; behavior and APIs may change |
| **GA**          | Yes           | Yes              | Yes              | Generally Available; full support          |
| **Maintenance** | No            | Critical only    | Yes              | No new features; stabilization only        |
| **End-of-Life** | No            | No               | No               | Unsupported; upgrade required              |

"GA" applies to the library's support commitments under this policy. Individual features or
integrations may ship at the **Preview** tier while the surrounding library is GA; such features are
labeled as Preview in their documentation and carry the best-effort guarantees above until promoted.

## Versioning and compatibility

dd-trace-rs follows [Semantic Versioning 2.0.0](https://semver.org/).

### Pre-1.0 (`0.y.z`) convention

While the crate is below `1.0.0`, it follows Cargo's SemVer convention: the **`y` (minor)**
component is the breaking-change axis. A bump of `y` (for example `0.3.x` to `0.4.0`) is treated as
a **major** release for the purposes of this policy, and a bump of `z` is treated as a
**minor/patch** release. Throughout this document, "major version" means the leading non-zero
version component (the `y` series while pre-1.0, the `x` series once `1.0.0` ships).

### What is covered by stability guarantees

- **Public API** of the published crates (`datadog-opentelemetry` and its public modules) is stable
  within a major version: no breaking changes outside a major bump.
- **Configuration** via environment variables and the public configuration builder is stable within
  a major version. Supported configuration keys are tracked in
  [`supported-configurations.json`](../supported-configurations.json).
- **Not covered:** anything documented as unstable/experimental, items marked `#[doc(hidden)]`,
  `_`-prefixed or `internal`/`private` modules, and the on-the-wire/transport details handled by
  libdatadog. These may change in any release.

### Deprecation

- Deprecations are announced in the `CHANGELOG.md` and, where possible, surfaced via Rust's
  `#[deprecated]` attribute.
- A deprecated public API is removed no earlier than the next major version, giving at least one
  major release cycle of notice.
- Migration steps for breaking changes are documented in the release notes for each major version.

## Version lifecycle

Datadog supports the current major version at the **GA** tier and the immediately previous major
version at the **Maintenance** tier:

| State           | Which version              | What you get                              |
| --------------- | -------------------------- | ----------------------------------------- |
| **GA**          | Latest major               | New features, bug fixes, security fixes   |
| **Maintenance** | Immediately previous major | Critical bug fixes and security fixes     |
| **End-of-Life** | All older majors           | Nothing                                   |

Concrete commitments:

- A major version is supported at GA from its release until the **next** major version reaches GA.
- When a new major reaches GA, the previous major enters **Maintenance for 6 months**, then reaches
  **End-of-Life**.
- Every GA major is supported for **at least 12 months** from its initial GA release, even if a
  successor ships sooner.
- Fixes land on the **latest minor/patch of a supported major**. Datadog does not backport to older
  minor releases; to receive a fix, upgrade to the latest release of a supported major.

Each GitHub release records its tier and, for superseded majors, the Maintenance and End-of-Life
dates.

## Rust toolchain support (MSRV)

The **Minimum Supported Rust Version (MSRV)** of the published `datadog-opentelemetry` crate is:

| Crate                   | MSRV       | Rust edition |
| ----------------------- | ---------- | ------------ |
| `datadog-opentelemetry` | **1.87.0** | 2021         |

> Companion crates may require a newer toolchain. The auto-instrumentation crates (for example
> `datadog-aws-lambda` and the `instrumentation` workspace), where published, declare their own,
> higher MSRV in their `Cargo.toml`. Always consult the target crate's manifest.

MSRV policy:

- The MSRV is documented in `Cargo.toml` (`rust-version`) and verified in CI on every change.
- The MSRV is **never raised in a patch release**. It may be raised in a major or minor release, and
  any increase is called out in the `CHANGELOG.md`.
- Datadog commits to supporting Rust stable releases that are **at least 6 months old**: the MSRV
  will not be newer than the Rust version that was current 6 months ago, except where a required
  dependency (including libdatadog or the OpenTelemetry crates) forces an earlier bump.
- Only the **stable** Rust channel is supported. The crates are expected to build on `beta` and
  `nightly`, but those channels are not a support commitment.

## OpenTelemetry and ecosystem dependency support

dd-trace-rs is built on the OpenTelemetry Rust SDK, which is itself pre-1.0 and introduces breaking
changes on most minor releases. Each dd-trace-rs release pins and supports a **single**
OpenTelemetry minor line:

| Dependency                           | Supported version |
| ------------------------------------ | ----------------- |
| `opentelemetry`                      | 0.31              |
| `opentelemetry_sdk`                  | 0.31              |
| `opentelemetry-otlp`                 | 0.31              |
| `opentelemetry-semantic-conventions` | 0.31              |
| `tracing-opentelemetry`              | 0.32              |
| `opentelemetry-appender-log`         | 0.31              |
| `log`                                | 0.4               |

Policy:

- An application using dd-trace-rs must depend on the **same OpenTelemetry minor version** that the
  installed dd-trace-rs release pins. Mixing OpenTelemetry minor versions is not supported.
- Because an OpenTelemetry minor bump is potentially breaking, dd-trace-rs treats it as a breaking
  change: the supported OpenTelemetry version is advanced in a major release (a `0.y` bump while
  pre-1.0) and announced in the `CHANGELOG.md`.
- The currently supported versions are also listed in the README `## Support` section, which is kept
  in sync with this document.

## Platform support

Platforms are tiered following the model used by the Rust project's own
[platform support](https://doc.rust-lang.org/nightly/rustc/platform-support.html):

- **Tier 1** — Built and tested in CI on every change. Fully supported.
- **Tier 2** — Expected to build and work; supported best-effort with limited or no CI coverage.
  Inherited from libdatadog support but not exercised end-to-end by dd-trace-rs CI.
- **Tier 3** — May build and work, but is untested and carries no support commitment.

The native components dd-trace-rs links (libdatadog) set the platform floor; the table below
reflects both that floor and what dd-trace-rs CI actually exercises.

| Platform                              | Architecture            | libc        | Tier        |
| ------------------------------------- | ----------------------- | ----------- | ----------- |
| Linux                                 | x86_64                  | glibc 2.17+ | **Tier 1**  |
| Linux                                 | aarch64 (arm64)         | glibc       | **Tier 1**  |
| macOS 12+                             | aarch64 (Apple Silicon) | n/a         | **Tier 1**  |
| Windows Server 2016+ / 10 / 11        | x86_64                  | MSVC        | **Tier 1**  |
| Linux                                 | x86_64                  | musl 1.2+   | **Tier 2**  |
| Linux                                 | aarch64 (arm64)         | musl 1.2+   | **Tier 2**  |
| macOS 12+                             | x86_64 (Intel)          | n/a         | **Tier 2**  |
| Windows                               | i686 (32-bit)           | MSVC        | **Tier 3**  |
| 32-bit Linux, WebAssembly, all others | —                       | —           | Unsupported |

Platform notes:

- **glibc floor.** The minimum glibc is **2.17** (validated in CI against a CentOS 7 build
  environment). Older glibc is not supported.
- **musl.** musl targets are supported by libdatadog and have no source-level exclusions in
  dd-trace-rs, but are not yet covered by dd-trace-rs CI, hence Tier 2.
- **Unix Domain Sockets.** Auto-detection of the Agent's UDS (`/var/run/datadog/apm.socket`) is a
  Linux optimization. On macOS and Windows the tracer transparently falls back to HTTP
  (`http://localhost:8126`); UDS is not required on any platform.
- **Linux-only features.** Publishing OpenTelemetry process context for eBPF-based profilers
  (`libdd-library-config`) is Linux-only and is skipped gracefully elsewhere.

Tier changes (promoting or dropping a platform) are not made silently: they require maintainer and
product alignment and are announced in the `CHANGELOG.md`.

## Datadog Agent compatibility

dd-trace-rs sends data to the Datadog Agent and must be paired with a
[supported Agent version on a supported platform](https://docs.datadoghq.com/agent/supported_platforms/).
The intersection of this policy's platform tiers and the Agent's supported platforms is what is
supported end-to-end. Running against an unsupported or end-of-life Agent is outside this policy.

## Security

- Security fixes are delivered to all versions that are **GA or in Maintenance**. End-of-Life
  versions do not receive security fixes — upgrade to a supported version.
- Report suspected vulnerabilities through Datadog's
  [vulnerability disclosure program](https://www.datadoghq.com/security/), not via public GitHub
  issues.
- Security-relevant fixes in dependencies (including libdatadog and the OpenTelemetry crates) are
  picked up by releasing an updated dd-trace-rs that bumps the affected dependency.

## How support is delivered

| Channel                                                         | Use for                                                |
| --------------------------------------------------------------- | ------------------------------------------------------ |
| [Datadog Support](https://www.datadoghq.com/support/)           | Account-backed support, production issues, escalations |
| [GitHub issues](https://github.com/DataDog/dd-trace-rs/issues)  | Bug reports, feature requests, questions               |
| [Vulnerability disclosure](https://www.datadoghq.com/security/) | Security reports (do not file public issues)           |

## Policy changes

This policy is reviewed on each major release and whenever a supported version, MSRV, OpenTelemetry
version, or platform tier changes. Material changes are recorded in the `CHANGELOG.md`. This policy
aligns with, and may be superseded by, Datadog's organization-wide APM library support policy.
