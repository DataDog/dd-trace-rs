# Releasing

## Datadog-opentelemetry

> [!CAUTION]
> Before releasing, check the Codex Security Scanning results board and ensure there are no new
> vulnerabilities discovered since the last release. If new vulnerabilities exist for the commit
> being released, discuss with the team whether releasing is safe, or if it should be delayed to
> resolve the vulnerability.

### Preparing the release with the GitHub workflow (recommended)

The **Release - Open a release PR** workflow (`.github/workflows/release-proposal-dispatch.yaml`)
runs the preparation on CI and opens the proposal pull request for you. It runs
`scripts/prepare-release.sh` (see below), commits the result as a verified (signed) commit, and
opens a `chore(release): proposal vX.Y.Z` PR that targets the base branch.

Trigger it from the GH UI ("Release - Open a release PR" → **Run workflow**) or with the CLI:

```text
gh workflow run release-proposal-dispatch.yaml --ref main \
  -f version=minor      # major | minor | patch | rc | beta | alpha, or an exact 0.6.0 / 0.6.0-rc.1
```

Inputs:

- `version` — the semver level or exact version to release.
- `base-branch` — branch to release from and target the PR at (default `main`).

> [!IMPORTANT]
> Always **dispatch the workflow from `main`** (`--ref main`). Minting the PR token is restricted to
> protected branches, so to cut a hotfix from an older line keep `--ref main` and set the
> `base-branch` input (e.g. `-f base-branch=hotfix/0.5.x`); do not dispatch directly from the
> hotfix branch. The proposal branch name is `release/proposal-v<version>`; the run fails if
> that branch already exists.

After the workflow opens the PR, review it (especially the generated changelog), merge it, then
continue with the tag and publish steps (6–9 below). The workflow does **not** tag or publish.

### Cutting a hotfix

A hotfix is released from a `hotfix/<major>.<minor>.x` branch instead of `main`, so `main` can keep
moving. The workflow always runs `main`'s YAML but the **base branch's**
`scripts/prepare-release.sh`, and releases up to and including v0.5.0 predate the release
automation — a branch cut from one of those tags carries none of it, so it has to be backported
before the workflow can prepare a proposal.

1. Create the branch from the release tag being patched, and push it:

```text
git switch -c hotfix/0.5.x datadog-opentelemetry-v0.5.0
git push -u origin hotfix/0.5.x
```

2. Land the fix on that branch (usually a cherry-pick from `main`). If the branch has no
   `scripts/prepare-release.sh`, backport the release automation too: that script, `cliff.toml`, and
   the `[package.metadata.release]` block in `datadog-opentelemetry/Cargo.toml`. Without them the
   workflow fails at the prepare step.

3. Dispatch the workflow **from `main`** (not from the hotfix branch), targeting the hotfix line:

```text
gh workflow run release-proposal-dispatch.yaml --ref main \
  -f version=patch -f base-branch=hotfix/0.5.x
```

4. Review and merge the proposal PR into `hotfix/0.5.x`, then tag that merge commit and push the
   tag to publish (steps 7–9 below). The changelog covers only the commits since the tag the
   branch was cut from, so it stays scoped to the hotfix.

### Preparing the release with the helper script

`scripts/prepare-release.sh` (which the workflow above runs) can also be run locally. It automates
most of the preparation below — the version bump, the version-reference updates, the changelog
generation, and the verification. It does **not** commit, tag, or publish, and it does not replace
the surrounding steps: you still bump libdatadog (step 1), review the incoming commits (step 2), and
merge, tag, and publish (steps 6–9) yourself.

The script handles the rest of the steps (3–5) and it requires `cargo-release`, `git-cliff`, and
`jq`.

Run it from the tip of the branch you are releasing (usually `main`, up to date with `origin`):

```text
./scripts/prepare-release.sh <minor|major|patch|VERSION>   # e.g. "minor" or "0.6.0"
```

It will:

- verify your checkout is in sync with the release branch,
- bump the workspace crate version,
- update the version references in `README.md`, `src/lib.rs`, the bug-report issue template, and the
  `datadog-aws-lambda` dependency pin (plus its lockfile),
- prepend a `CHANGELOG.md` section listing the commits since the previous release tag,
- verify that the rustdocs build and that the crate publishes cleanly (a `cargo publish` dry-run).

Then review the working tree — especially the generated changelog, pruning it to user-facing
changes — and commit.

Because the changelog is built from the commit history since the previous release tag, the script
needs the full history and tags — it refuses to run on a shallow clone. When invoking it from CI,
check out with `fetch-depth: 0` (which also fetches tags) so the changelog range resolves correctly.

The manual steps below remain valid and can always be followed instead.

### Manual steps

1. Bump libdatadog dependencies to their latest version. Unless there are specific reasons not to,
   we should make a fresh release of libdatadog crates just before dd-trace-rs releases to benefit
   from upgrades

2. Check the commits that are going in the new release, by creating a draft release in github
   <https://github.com/DataDog/dd-trace-rs/releases/new>

3. Append to the CHANGELOG.md, adding only additions/removal/fixes that affect users

4. Check that the README and rustdocs are up to date with the current feature set and that they
   render correctly on github. rustdocs can be generated using the following command

```text
RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc -p datadog-opentelemetry --no-deps
```

5. Merge all necessary modifications, then bump the crate version to the one you'd like to release.
   Grep and replace all occurrences of the current version number, as it is exposed also in
   documentation and in links to doc.rs

6. Merge the bump commit in `main`

7. Tag the bump commit with the release version. The tag should follow the following format:
   `datadog-opentelemetry-v0.0.0`, then push it to github.

```text
VERSION="0.0.0" # Placeholder, please replace!
BUMP_COMMIT_HASH="PUT THE HASH HERE" # Placeholder, please replace!
TAG="datadog-opentelemetry-v$VERSION"
git tag $TAG main -m "Release v$VERSION of datadog-opentelemetry"
echo "Tagged release $TAG"
```

> [!CAUTION]
> Pushing the tag to github will trigger the release automation. Run `git log`, and check that the
> tag name and tagged commit are correct before running the following command

```text
git push origin $TAG
```

8. Once the tag has been pushed, the publish job will need to be approved by another member of the
   apm-rust github group

9. Make a github release, from the previous release to the new tag. You can auto-generate the
   release notes. <https://github.com/DataDog/dd-trace-rs/releases/new>
