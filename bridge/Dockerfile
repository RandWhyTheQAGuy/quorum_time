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
# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Aegis Bridge Sidecar
#
# Matches the base OS of the existing aegis-clock-server image (Ubuntu 24.04)
# so the .so ABI, glibc version, and OpenSSL headers are identical.
#
# Build:
#   docker build -t yourorg/aegis-bridge:latest -f bridge/Dockerfile .
#
# The build context is the PROJECT ROOT (not the bridge/ subdirectory) so
# the compiled _uml001 .so can be copied in from build/.
# ---------------------------------------------------------------------------

FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.14 \
    python3.14-dev \
    python3-pip \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Use python3.14 explicitly everywhere
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.14 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.14 1

# ---------------------------------------------------------------------------
# Builder stage - install Python deps and run grpc codegen
# ---------------------------------------------------------------------------
FROM base AS builder

WORKDIR /build

# Install pip deps into a prefix we can COPY across
COPY bridge/pyproject.toml /build/pyproject.toml
RUN pip install --break-system-packages --no-cache-dir \
    fastapi>=0.111.0 \
    "uvicorn[standard]>=0.29.0" \
    grpcio>=1.78.0 \
    grpcio-tools>=1.78.0 \
    protobuf>=6.31.1 \
    websockets>=12.0

# Copy bridge source
COPY bridge/ /build/bridge/

# Generate gRPC stubs at image-build time so the container doesn't need
# write access to the bridge/ directory at runtime.
RUN python3 -m grpc_tools.protoc \
    -I/build/bridge/proto \
    --python_out=/build/bridge \
    --grpc_python_out=/build/bridge \
    /build/bridge/proto/bridge.proto

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM base AS runtime

# Non-root user matching fsGroup: 1000 in deployment.yaml
RUN groupadd -g 1000 aegis && useradd -u 1000 -g aegis -s /bin/false -d /app aegis

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.14 /usr/local/lib/python3.14
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# Copy bridge package (with generated stubs)
COPY --from=builder /build/bridge /app/bridge

# Copy compiled C++ extension from the host build directory.
# The Makefile / CI pipeline must have run `cmake --build` before docker build.
COPY build/_uml001*.so /app/

# Vault storage mount point - matches volumeMount in deployment.yaml
RUN mkdir -p /var/lib/aegis/vault && chown aegis:aegis /var/lib/aegis/vault

USER aegis

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8080 8081 9090 1123/udp

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python3 -c "import socket; s=socket.create_connection(('127.0.0.1',8080),2); s.close()" || exit 1

ENTRYPOINT ["python3", "-m", "bridge.server_main"]
