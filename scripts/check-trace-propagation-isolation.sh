#!/usr/bin/env bash

# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

# Verifies that datadog-trace-propagation stays an independent, publishable crate:
# it must not depend (directly or transitively, on normal, build, or dev edges)
# on any libdd-* crate, and it must remain a workspace member that
# datadog-opentelemetry re-exports as its `propagation` module.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

CRATE="datadog-trace-propagation"

fail() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

# 1. The crate must be a workspace member.
if ! cargo metadata --format-version=1 --no-deps 2>/dev/null \
    | grep -q "\"name\":\"${CRATE}\""; then
    fail "${CRATE} is not a workspace member. Add it to [workspace] members in the root Cargo.toml."
fi
echo "ok: ${CRATE} is a workspace member"

# 2. No libdd-* dependencies on normal or build edges (includes transitive deps).
if cargo tree --package "${CRATE}" --edges normal,build --prefix none \
    | grep -E '^libdd-'; then
    fail "${CRATE} depends on libdd-* crates via normal/build edges. The crate must have zero libdd-* dependencies."
fi
echo "ok: no libdd-* dependencies on normal/build edges"

# 3. No libdd-* dependencies through dev-dependencies or their transitive normal/build edges.
if cargo tree --package "${CRATE}" --edges normal,build,dev --prefix none \
    | grep -E '^libdd-'; then
    fail "${CRATE} depends on libdd-* crates through its dev-dependency graph. The crate must have zero libdd-* dependencies (including transitive dev-dependencies)."
fi
echo "ok: no libdd-* dependencies in the complete dev-dependency graph"

# 4. datadog-opentelemetry must depend on the crate (it re-exports it as `propagation`).
if ! cargo tree --package datadog-opentelemetry --edges normal --prefix none \
    | grep -q "^${CRATE}"; then
    fail "datadog-opentelemetry does not depend on ${CRATE}. Its public \`propagation\` module is a re-export of that crate."
fi
echo "ok: datadog-opentelemetry depends on ${CRATE}"

echo -e "${GREEN}All ${CRATE} isolation guardrails passed.${NC}"
