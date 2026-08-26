#!/usr/bin/env bash

# Copyright 2021-Present Datadog, Inc. https://www.datadoghq.com/
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Keep in sync with: scripts/Dockerfile.license (ARG TOOL_VERSION) and .github/workflows/lint.yaml (cache key + install step)
TOOL_VERSION="1.0.6"
INSTALL_CMD="cargo install dd-rust-license-tool --version \"${TOOL_VERSION}\" --locked"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

usage() {
    cat <<EOF
Usage: $0 WORKSPACE_PATH [WORKSPACE_PATH...]

Generate third-party license CSV files.

Each WORKSPACE_PATH must point to a Cargo workspace directory. The generated file is written next
to that workspace's Cargo.toml as LICENSE-3rdparty.csv.

Examples:
  $0 .
  $0 instrumentation
  $0 . instrumentation
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

if [ "$#" -eq 0 ]; then
    echo "ERROR: at least one workspace path is required."
    echo ""
    usage
    exit 1
fi

WORKSPACE_PATHS=("$@")

normalize_workspace_path() {
    local workspace_path="$1"

    workspace_path="${workspace_path#./}"
    workspace_path="${workspace_path%/}"
    if [ -z "${workspace_path}" ]; then
        workspace_path="."
    fi
    echo "${workspace_path}"
}

run_tool() {
    local workspace_path
    local manifest
    local output

    workspace_path="$(normalize_workspace_path "$1")"
    manifest="${workspace_path}/Cargo.toml"
    output="${workspace_path}/LICENSE-3rdparty.csv"

    if [ ! -f "${manifest}" ]; then
        echo "ERROR: ${workspace_path} is not a Cargo workspace directory."
        echo "Expected manifest at: ${manifest}"
        exit 1
    fi

    echo "Generating ${output}..."
    dd-rust-license-tool --manifest-path "${manifest}" dump > "${output}"
}

run_native() {
    cd "${ROOT_DIR}"
    for workspace_path in "${WORKSPACE_PATHS[@]}"; do
        run_tool "${workspace_path}"
    done
}

run_docker() {
    local manifest
    local output

    if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
        echo "ERROR: Docker is not running. Please start the Docker daemon and try again."
        exit 1
    fi
    export DOCKER_BUILDKIT=1
    echo "Building license tool container..."
    docker build \
        --progress=plain \
        -t dd-trace-rs-dd-license-tool \
        -f "${ROOT_DIR}/scripts/Dockerfile.license" \
        "${ROOT_DIR}"
    for workspace_path in "${WORKSPACE_PATHS[@]}"; do
        workspace_path="$(normalize_workspace_path "${workspace_path}")"
        manifest="${workspace_path}/Cargo.toml"
        output="${workspace_path}/LICENSE-3rdparty.csv"

        if [ ! -f "${ROOT_DIR}/${manifest}" ]; then
            echo "ERROR: ${workspace_path} is not a Cargo workspace directory."
            echo "Expected manifest at: ${manifest}"
            exit 1
        fi

        echo "Generating ${output}..."
        docker run --rm dd-trace-rs-dd-license-tool --manifest-path "${manifest}" dump > "${ROOT_DIR}/${output}"
    done
}

has_matching_license_tool() {
    cargo install --list 2>/dev/null | grep -qF "dd-rust-license-tool v${TOOL_VERSION}:" \
        || { command -v dd-rust-license-tool > /dev/null && [ "$(dd-rust-license-tool --version | awk '{print $2}')" = "${TOOL_VERSION}" ]; }
}

installed_license_tool_version() {
    local version

    version="$(cargo install --list 2>/dev/null | grep "^dd-rust-license-tool v" | awk '{print $2}' | tr -d ':' || true)"
    if [ -n "${version}" ]; then
        echo "${version}"
    elif command -v dd-rust-license-tool > /dev/null; then
        dd-rust-license-tool --version | awk '{print $2}'
    fi
}

if has_matching_license_tool; then
    run_native
else
    INSTALLED_VERSION="$(installed_license_tool_version)"

    echo "dd-rust-license-tool v${TOOL_VERSION} is not installed."
    if [ -n "${INSTALLED_VERSION}" ]; then
        echo "Found installed version: ${INSTALLED_VERSION}"
    fi
    echo ""
    echo "To install v${TOOL_VERSION} locally, run:"
    echo "  ${INSTALL_CMD}"
    echo ""
    echo "How would you like to proceed?"
    echo "  1) Install dd-rust-license-tool v${TOOL_VERSION} locally and run"
    echo "  2) Use Docker (requires Docker daemon to be running)"
    if [ -n "${INSTALLED_VERSION}" ]; then
        echo "  3) Run with the installed version (${INSTALLED_VERSION})"
        read -rp "Enter 1, 2, or 3: " choice
    else
        read -rp "Enter 1 or 2: " choice
    fi

    case "${choice}" in
        1)
            echo "Installing dd-rust-license-tool v${TOOL_VERSION}..."
            eval "${INSTALL_CMD}"
            run_native
            ;;
        2)
            run_docker
            ;;
        3)
            if [ -n "${INSTALLED_VERSION}" ]; then
                run_native
            else
                echo "Invalid choice. Exiting."
                exit 1
            fi
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
fi

echo ""
echo "Successfully generated license CSV file(s)."
echo "Please review and commit the changes."
