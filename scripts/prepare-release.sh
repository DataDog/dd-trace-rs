#!/usr/bin/env bash

# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

# Prepares a datadog-opentelemetry release *proposal* in the working tree:
#   1. bumps the (workspace-shared) crate version,
#   2. updates version references (README, lib.rs, bug report template) via
#      cargo-release `pre-release-replacements`,
#   3. prepends a changelog section listing the commits since the last release (via git-cliff),
#   4. verifies the result (rustdocs build, reference consistency, publish dry-run).
#
# It intentionally does NOT commit, tag, publish, or push. The caller (the
# release-proposal workflow) opens the PR; tagging and publishing remain manual
# (git tag -> .github/workflows/publish.yaml -> scripts/publish-crate.sh).

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

PACKAGE="datadog-opentelemetry"
BASE_BRANCH="main"
DOC_TOOLCHAIN="nightly"
RUN_PUBLISH_DRY_RUN=true
ALLOW_DIRTY=false
CHECK_SYNC=true

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <LEVEL|VERSION>

Prepares a $PACKAGE release proposal in the working tree (no commit/tag/publish).

Arguments:
    <LEVEL|VERSION>     A semver level (major|minor|patch|release|rc|beta|alpha)
                        or an exact version (e.g. 0.5.0).

Options:
    -h, --help                  Show this help message
        --base-branch <NAME>    Branch to release from and verify sync against (default: $BASE_BRANCH).
                                Use a hotfix/release branch to cut a hotfix from an older line.
        --allow-dirty           Proceed even if the working tree has uncommitted changes
        --no-sync-check         Skip verifying HEAD matches the latest origin/<base-branch> commit
        --no-publish-dry-run    Skip the 'cargo publish --dry-run' verification step
        --doc-toolchain <NAME>  Rust toolchain used for the rustdocs build (default: $DOC_TOOLCHAIN)

Examples:
    $(basename "$0") minor
    $(basename "$0") 0.5.0
    $(basename "$0") --base-branch hotfix/0.5.x 0.5.1
EOF
}

LEVEL_OR_VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        --allow-dirty) ALLOW_DIRTY=true; shift ;;
        --no-sync-check) CHECK_SYNC=false; shift ;;
        --no-publish-dry-run) RUN_PUBLISH_DRY_RUN=false; shift ;;
        --doc-toolchain) DOC_TOOLCHAIN="$2"; shift 2 ;;
        -*) echo -e "${RED}Unknown option: $1${NC}" >&2; usage; exit 1 ;;
        *)
            if [ -n "$LEVEL_OR_VERSION" ]; then
                echo -e "${RED}❌ ERROR: unexpected extra argument '$1'${NC}" >&2
                exit 1
            fi
            LEVEL_OR_VERSION="$1"; shift ;;
    esac
done

if [ -z "$LEVEL_OR_VERSION" ]; then
    echo -e "${RED}❌ ERROR: missing <LEVEL|VERSION>${NC}" >&2
    echo "" >&2
    usage
    exit 1
fi

# A dirty tree means the resulting commit would include unrelated changes, so fail early with a
# clear message unless the caller explicitly opts in with --allow-dirty.
if [ "$ALLOW_DIRTY" != true ] && [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}❌ ERROR: working tree is not clean. Commit or stash changes first, or pass --allow-dirty.${NC}" >&2
    exit 1
fi

# The proposal must be cut from the tip of the base branch; a stale checkout would list the wrong
# commits and bump from the wrong base. Verify HEAD matches the freshly-fetched origin/$BASE_BRANCH.
if [ "$CHECK_SYNC" = true ]; then
    echo -e "${BLUE}--- Checking sync with origin/$BASE_BRANCH ---${NC}"
    if ! git fetch --quiet origin "$BASE_BRANCH"; then
        echo -e "${RED}❌ ERROR: failed to fetch origin/$BASE_BRANCH${NC}" >&2
        exit 1
    fi
    local_head="$(git rev-parse HEAD)"
    remote_head="$(git rev-parse FETCH_HEAD)"
    if [ "$local_head" != "$remote_head" ]; then
        echo -e "${RED}❌ ERROR: HEAD is not in sync with the latest origin/$BASE_BRANCH commit.${NC}" >&2
        echo "   HEAD:                $local_head" >&2
        echo "   origin/$BASE_BRANCH: $remote_head" >&2
        echo "   Update to the latest $BASE_BRANCH (e.g. git pull --ff-only origin $BASE_BRANCH), or pass --no-sync-check." >&2
        exit 1
    fi
    echo -e "${GREEN}✓ In sync with origin/$BASE_BRANCH ($remote_head)${NC}"
fi

if ! command -v git-cliff >/dev/null 2>&1; then
    echo -e "${RED}❌ ERROR: git-cliff is required to generate the changelog (install: cargo install git-cliff).${NC}" >&2
    exit 1
fi

crate_version() {
    cargo metadata --format-version=1 --no-deps \
        | jq -r --arg p "$PACKAGE" '.packages[] | select(.name == $p) | .version'
}

PREV_VERSION="$(crate_version)"
echo -e "${BLUE}Current version: $PREV_VERSION${NC}"

# Validate the argument: either a known semver level, or an exact version that is well-formed
# and strictly greater than the current version. Levels are left to cargo-release, which always
# produces a higher version.
case "$LEVEL_OR_VERSION" in
    major|minor|patch|release|rc|beta|alpha) ;;
    *)
        if ! printf '%s' "$LEVEL_OR_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
            echo -e "${RED}❌ ERROR: '$LEVEL_OR_VERSION' is not a valid version or release level${NC}" >&2
            echo "   Expected a level (major|minor|patch|release|rc|beta|alpha) or a semver version (e.g. 0.6.0)." >&2
            exit 1
        fi
        highest="$(printf '%s\n%s\n' "$PREV_VERSION" "$LEVEL_OR_VERSION" | sort -V | tail -n1)"
        if [ "$LEVEL_OR_VERSION" = "$PREV_VERSION" ] || [ "$highest" != "$LEVEL_OR_VERSION" ]; then
            echo -e "${RED}❌ ERROR: version $LEVEL_OR_VERSION must be greater than the current version $PREV_VERSION${NC}" >&2
            exit 1
        fi
        ;;
esac

# 1. Bump the version (shared across the workspace via [workspace.package]).
echo -e "${BLUE}--- Bumping version ($LEVEL_OR_VERSION) ---${NC}"
cargo release version "$LEVEL_OR_VERSION" --package "$PACKAGE" --execute --no-confirm

# 2. Apply pre-release replacements (docs + changelog).
echo -e "${BLUE}--- Updating version references and changelog ---${NC}"
cargo release replace --package "$PACKAGE" --execute --no-confirm

NEW_VERSION="$(crate_version)"
echo -e "${GREEN}Bumped $PREV_VERSION -> $NEW_VERSION${NC}"

if [ "$NEW_VERSION" = "$PREV_VERSION" ]; then
    echo -e "${RED}❌ ERROR: version did not change${NC}" >&2
    exit 1
fi

# The instrumentation crates are a separate workspace, so cargo-release does not touch them.
# Bump their datadog-opentelemetry dependency pin (kept as major.minor to match the existing
# style) and refresh that workspace's lockfile so it stays consistent with the released version.
version_req="$(printf '%s' "$NEW_VERSION" | cut -d. -f1,2)"
lambda_manifest="instrumentation/datadog-aws-lambda/Cargo.toml"
echo -e "${BLUE}--- Bumping datadog-opentelemetry pin in $lambda_manifest to $version_req ---${NC}"
sed -i -E "s|(datadog-opentelemetry = \{ version = \")[^\"]+|\1${version_req}|g" "$lambda_manifest"
cargo update --manifest-path instrumentation/Cargo.toml --package datadog-opentelemetry

# 3. Prepend a changelog section listing the commits since the last release.
echo -e "${BLUE}--- Populating changelog for $NEW_VERSION ---${NC}"
CHANGELOG="$PACKAGE/CHANGELOG.md"
# The previous tag: the most recent release tag reachable from HEAD (not merely the
# highest version, which may live on another branch).
previous_tag="$(git describe --tags --abbrev=0 --match "$PACKAGE-v*" 2>/dev/null || true)"
if [ -n "$previous_tag" ]; then
    cliff_range=("$previous_tag..HEAD")
    echo "Listing commits since $previous_tag" >&2
else
    cliff_range=()   # no prior release tag: include all history
    echo "No previous $PACKAGE release tag found; listing all history" >&2
fi

# git-cliff renders the entries: a plain list with PR links, omitting chore/ci/docs/test
# (see cliff.toml). Strip any leading blank lines it emits before the first bullet.
commits="$(git cliff --config cliff.toml "${cliff_range[@]}" 2>/dev/null | sed '/./,$!d')"
if [ -z "$commits" ]; then
    commits="- _No changes._"
fi

# Insert a new "## <version> (<date>)" section right after the "# Changelog" title line.
release_date="$(date +'%b %d, %Y')"
tmp="$(mktemp)"
{
    printf '# Changelog\n\n'
    printf '## %s (%s)\n\n' "$NEW_VERSION" "$release_date"
    printf '%s\n\n' "$commits"
    # everything after the original "# Changelog" title line (drop its following blank line)
    tail -n +2 "$CHANGELOG" | sed '1{/^$/d}'
} > "$tmp"
mv "$tmp" "$CHANGELOG"

# 3a. Verify rustdocs still build (mirrors docs/releasing.md).
echo -e "${BLUE}--- Building rustdocs (+$DOC_TOOLCHAIN) ---${NC}"
RUSTDOCFLAGS="--cfg docsrs" cargo "+$DOC_TOOLCHAIN" doc --package "$PACKAGE" --no-deps

# 3b. Verify every version reference now points at the new version.
echo -e "${BLUE}--- Verifying version references ---${NC}"
fail=0
check() {
    local description="$1" file="$2" pattern="$3"
    if ! grep -qF "$pattern" "$file"; then
        echo -e "${RED}  ✗ $description not updated in $file (expected '$pattern')${NC}" >&2
        fail=1
    else
        echo -e "${GREEN}  ✓ $description${NC}"
    fi
}
check "README install snippet"  "README.md"                          "datadog-opentelemetry = { version = \"$NEW_VERSION\" }"
check "README docs.rs link"     "README.md"                          "docs.rs/datadog-opentelemetry/$NEW_VERSION/"
check "lib.rs install snippet"  "$PACKAGE/src/lib.rs"                "datadog-opentelemetry = { version = \"$NEW_VERSION\" }"
check "bug report template"     ".github/ISSUE_TEMPLATE/bug_report.yml" "placeholder: \"$NEW_VERSION\""
check "aws-lambda dep pin"      "$lambda_manifest"                   "datadog-opentelemetry = { version = \"$version_req\""
check "changelog section"       "$PACKAGE/CHANGELOG.md"              "## $NEW_VERSION"
if [ "$fail" -ne 0 ]; then
    echo -e "${RED}❌ ERROR: version reference verification failed${NC}" >&2
    exit 1
fi

# 3c. Verify the crate still packages/publishes cleanly against the updated lockfile.
if [ "$RUN_PUBLISH_DRY_RUN" = true ]; then
    echo -e "${BLUE}--- cargo publish --dry-run ---${NC}"
    cargo publish --package "$PACKAGE" --all-features --locked --dry-run --allow-dirty
fi

echo -e "${GREEN}✓ Release proposal prepared: $PREV_VERSION -> $NEW_VERSION${NC}"

# Expose results to GitHub Actions when running in CI.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "prev_version=$PREV_VERSION"
        echo "new_version=$NEW_VERSION"
    } >> "$GITHUB_OUTPUT"
fi
