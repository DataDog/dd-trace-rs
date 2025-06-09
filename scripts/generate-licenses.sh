#!/bin/bash

# Copyright 2024-present Datadog, Inc.
#
# SPDX-License-Identifier: Apache-2.0

# This script generates the LICENSE-3rdparty.csv file using a Docker container
# to ensure the environment matches the CI runner (Linux). This avoids
# platform-specific differences in the dependency tree.

set -euo pipefail

# 1. Check if Docker is installed and the daemon is running.
if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
    echo "ERROR: Docker is not running. Please start the Docker daemon and try again."
    exit 1
fi

# 2. Ensure BuildKit is enabled for efficient caching
export DOCKER_BUILDKIT=1

echo "Creating temporary cargo config..."
mkdir -p .cargo
printf "[registries.crates-io]\nprotocol = \"git\"\n" > .cargo/config.toml

echo "Building license tool container with caching..."
docker build \
    --progress=plain \
    -t dd-license-tool \
    -f scripts/Dockerfile.license \
    .

echo "Generating LICENSE-3rdparty.csv..."
docker run --rm \
    -v "$(pwd)":/usr/src/app \
    -u "$(id -u):$(id -g)" \
    dd-license-tool > LICENSE-3rdparty.csv

echo "Cleaning up..."
rm -rf .cargo/config.toml

echo ""
echo "✅ Successfully generated LICENSE-3rdparty.csv."
echo "Please review and commit the changes." 