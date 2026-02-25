#!/usr/bin/env bash
# Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

# Cross-compile all Rust Lambda examples for ARM64 and package as bootstrap.zip
# for CDK deployment.
#
# Prerequisites: cargo-zigbuild, zig
#
# Usage:
#   ./scripts/build-examples.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${PROJECT_DIR}/../../.." && pwd)"
OUTPUT_DIR="${PROJECT_DIR}/cdk/rust-binaries"
TARGET="aarch64-unknown-linux-gnu"

EXAMPLES=(
  sqs-producer
  sqs-consumer
  sns-producer
  sns-consumer
  eventbridge-producer
  eventbridge-consumer
)

mkdir -p "${OUTPUT_DIR}"

echo "Building ${#EXAMPLES[@]} examples for ${TARGET}..."

cargo zigbuild \
  --manifest-path "${PROJECT_DIR}/Cargo.toml" \
  --examples \
  --target "${TARGET}" \
  --release

for name in "${EXAMPLES[@]}"; do
  bin="${WORKSPACE_ROOT}/target/${TARGET}/release/examples/${name}"
  if [[ ! -f "${bin}" ]]; then
    echo "ERROR: binary not found: ${bin}"
    exit 1
  fi

  zip_path="${OUTPUT_DIR}/${name}.zip"
  # Lambda expects the binary to be named "bootstrap"
  cp "${bin}" "${OUTPUT_DIR}/bootstrap"
  (cd "${OUTPUT_DIR}" && zip -j "${zip_path}" bootstrap)
  rm "${OUTPUT_DIR}/bootstrap"
  echo "  ${name}.zip ($(du -h "${zip_path}" | cut -f1))"
done

echo "All examples built and packaged in ${OUTPUT_DIR}/"
