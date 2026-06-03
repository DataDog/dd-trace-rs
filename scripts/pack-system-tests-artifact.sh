#!/usr/bin/env bash
# Copyright 2026-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0
#
# Pack [workspace] members → OUTPUT_DIR for system tests.
# Stable entry point: reads members from Cargo.toml, copies root dirs.
#
# Usage: ./scripts/pack-system-tests-artifact.sh [OUTPUT_DIR]
#   OUTPUT_DIR  defaults to ./binaries/dd-trace-rs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${REPO_ROOT}/binaries/dd-trace-rs}"

cd "${REPO_ROOT}"

mkdir -p "${OUTPUT_DIR}"

# Read [workspace] members from Cargo.toml.
# Glob patterns expanded; nested paths deduplicated — only unique root dirs
# need to be copied (a root copy already includes nested members).
# tomllib = Python stdlib (3.11+), no extra deps.
mapfile -t ROOTS < <(python3 - <<'EOF'
import glob, tomllib
with open("Cargo.toml", "rb") as f:
    patterns = tomllib.load(f)["workspace"]["members"]
members = [p for pat in patterns for p in (sorted(glob.glob(pat)) or [pat])]
# Drop member if another member is a strict path prefix of it.
for m in members:
    if not any(m.startswith(o + "/") for o in members if o != m):
        print(m)
EOF
)

for root in "${ROOTS[@]}"; do
    # Ensure parent dir exists for multi-segment paths.
    mkdir -p "${OUTPUT_DIR}/$(dirname "${root}")"
    cp -r "${root}" "${OUTPUT_DIR}/${root}"
done

# Workspace-level files.
cp Cargo.toml Cargo.lock "${OUTPUT_DIR}/"
mkdir -p "${OUTPUT_DIR}/.cargo"
cp .cargo/config.toml "${OUTPUT_DIR}/.cargo/config.toml"

echo "packed ${#ROOTS[@]} workspace roots → ${OUTPUT_DIR}"
ls -lA "${OUTPUT_DIR}"
