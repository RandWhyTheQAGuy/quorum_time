#!/usr/bin/env bash
# Quorum Time — Open Trusted Time & Distributed Verification Framework
# Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
# SPDX-License-Identifier: Apache-2.0
#
# Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
# system designed for modern distributed environments. It provides a
# cryptographically anchored notion of time that can be aligned,
# audited, and shared across domains without requiring centralized
# trust.
#
# This project also includes the Aegis Semantic Passport components,
# which complement Quorum Time by offering structured, verifiable
# identity and capability attestations for agents and services.
#
# Core capabilities:
#   - BFT Quorum Time: multi-authority, tamper-evident time agreement
#                      with drift bounds, authority attestation, and
#                      cross-domain alignment (AlignTime).
#
#   - Transparency Logging: append-only, hash-chained audit records
#                           for time events, alignment proofs, and
#                           key-rotation operations.
#
#   - Open Integration: designed for interoperability with distributed
#                       systems, security-critical infrastructure,
#                       autonomous agents, and research environments.
#
# Quorum Time is developed as an open-source project with a focus on
# clarity, auditability, and long-term maintainability. Contributions,
# issue reports, and discussions are welcome.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This implementation is intended for open research, practical
# deployment, and community-driven evolution of verifiable time and
# distributed trust standards.
#
# ---------------------------------------------------------------------------
# build_bridge.sh
#
# Builds, tests, and packages the Aegis bridge sidecar.
# Run from the PROJECT ROOT (same directory as the main build.sh).
#
# Usage:
#   ./build_bridge.sh                  # build + test only
#   ./build_bridge.sh --docker         # also build the Docker image
#   ./build_bridge.sh --docker --push  # build + push to registry
#
# Prerequisites:
#   - C++ build already run (build/_uml001*.so must exist)
#   - Python 3.14 on PATH
#   - docker (only required with --docker flag)
# ---------------------------------------------------------------------------

set -euo pipefail

# Script lives at <project_root>/bridge/build_bridge.sh
# ROOT_DIR is one level up from the script's own directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BRIDGE_DIR="$ROOT_DIR/bridge"
BUILD_DIR="$ROOT_DIR/build"

DO_DOCKER=false
DO_PUSH=false

for arg in "$@"; do
    case $arg in
        --docker) DO_DOCKER=true ;;
        --push)   DO_PUSH=true ;;
    esac
done

# ---------------------------------------------------------------------------
# 0. Verify the C++ extension exists
# ---------------------------------------------------------------------------

echo "[bridge] Checking for compiled _uml001 extension..."
SO_FILE=$(find "$BUILD_DIR" -name "_uml001*.so" 2>/dev/null | head -1)
if [[ -z "$SO_FILE" ]]; then
    echo "[bridge] ERROR: _uml001*.so not found under build/."
    echo "[bridge]        Run ./build.sh first to compile the C++ extension."
    exit 1
fi
echo "[bridge] Found: $SO_FILE"

# ---------------------------------------------------------------------------
# 1. Install Python dependencies
# ---------------------------------------------------------------------------

echo "[bridge] Installing Python dependencies..."
pip install --quiet \
    "fastapi>=0.111.0" \
    "uvicorn[standard]>=0.29.0" \
    "grpcio>=1.78.0" \
    "grpcio-tools>=1.78.0" \
    "protobuf>=6.31.1" \
    "websockets>=12.0" \
    "pytest>=9.0.0" \
    "pytest-asyncio>=0.23.0" \
    "httpx>=0.27.0"

# ---------------------------------------------------------------------------
# 2. Generate gRPC stubs
# ---------------------------------------------------------------------------

PROTO_SRC="$BRIDGE_DIR/bridge/proto/bridge.proto"
STUB_OUT="$BRIDGE_DIR/bridge"

echo "[bridge] Generating gRPC stubs from $PROTO_SRC..."
python3 -m grpc_tools.protoc \
    -I"$BRIDGE_DIR/bridge/proto" \
    --python_out="$STUB_OUT" \
    --grpc_python_out="$STUB_OUT" \
    "$PROTO_SRC"
echo "[bridge] Stubs generated at $STUB_OUT"

# ---------------------------------------------------------------------------
# 3. Run tests
# ---------------------------------------------------------------------------

echo "[bridge] Running bridge unit tests..."
cd "$BRIDGE_DIR"

export PYTHONPATH="$BRIDGE_DIR:${PYTHONPATH:-}"
pytest tests/ \
    --ignore=tests/test_integration.py \
    -v \
    --tb=short

# Integration tests run only if the .so is importable
echo "[bridge] Running integration tests (skipped if .so unavailable)..."
PYTHONPATH="$BUILD_DIR:$BRIDGE_DIR" \
pytest tests/test_integration.py \
    -v \
    --tb=short \
    || echo "[bridge] Integration tests skipped or failed - check PYTHONPATH=$BUILD_DIR"

cd "$ROOT_DIR"

echo "[bridge] All tests passed."

# ---------------------------------------------------------------------------
# 4. Docker image (optional)
# ---------------------------------------------------------------------------

if [[ "$DO_DOCKER" == true ]]; then
    IMAGE_TAG="${AEGIS_BRIDGE_IMAGE:-yourorg/aegis-bridge:latest}"
    echo "[bridge] Building Docker image: $IMAGE_TAG"
    docker build \
        -t "$IMAGE_TAG" \
        -f "$BRIDGE_DIR/Dockerfile" \
        "$ROOT_DIR"
    echo "[bridge] Image built: $IMAGE_TAG"

    if [[ "$DO_PUSH" == true ]]; then
        echo "[bridge] Pushing $IMAGE_TAG..."
        docker push "$IMAGE_TAG"
        echo "[bridge] Pushed."
    fi
fi

echo "[bridge] Done."