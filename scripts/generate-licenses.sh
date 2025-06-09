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

echo "Ensuring the 'scripts' directory exists for our .cargo/config.toml..."
mkdir -p scripts

echo "Creating a temporary cargo config to force git protocol..."
printf "[registries.crates-io]\nprotocol = \"git\"\n" > scripts/config.toml

echo "Generating LICENSE-3rdparty.csv inside a Docker container..."

# 2. Use a specific Rust Docker image to ensure a consistent environment.
# We mount the project directory into the container and execute the commands.
docker run --rm \
    -v "$(pwd)":/usr/src/app \
    -v "$(pwd)/scripts/config.toml":/usr/src/app/.cargo/config.toml \
    -w /usr/src/app \
    rust:1.82-slim \
    bash -c "
        set -e
        echo '--> Installing license tool...'
        cargo install --git https://github.com/DataDog/rust-license-tool.git dd-rust-license-tool
        
        echo '--> Generating license file...'
        dd-rust-license-tool dump > LICENSE-3rdparty.csv
    "

# 3. Clean up the temporary config file.
rm scripts/config.toml

echo ""
echo "✅ Successfully generated LICENSE-3rdparty.csv."
echo "Please review and commit the changes." 