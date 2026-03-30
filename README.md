<!--
  Quorum Time — Open Trusted Time & Distributed Verification Framework
  Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
  SPDX-License-Identifier: Apache-2.0

  Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
  system designed for modern distributed environments. It provides a
  cryptographically anchored notion of time that can be aligned,
  audited, and shared across domains without requiring centralized
  trust.

  This project also includes the Aegis Semantic Passport components,
  which complement Quorum Time by offering structured, verifiable
  identity and capability attestations for agents and services.

  Core capabilities:
    - BFT Quorum Time: multi-authority, tamper-evident time agreement
                       with drift bounds, authority attestation, and
                       cross-domain alignment (AlignTime).

    - Transparency Logging: append-only, hash-chained audit records
                            for time events, alignment proofs, and
                            key-rotation operations.

    - Open Integration: designed for interoperability with distributed
                        systems, security-critical infrastructure,
                        autonomous agents, and research environments.

  Quorum Time is developed as an open-source project with a focus on
  clarity, auditability, and long-term maintainability. Contributions,
  issue reports, and discussions are welcome.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0

  This implementation is intended for open research, practical
  deployment, and community-driven evolution of verifiable time and
  distributed trust standards.

-->
# Quorum Time

Open, verifiable, Byzantine-resilient trusted-time framework with deterministic event orchestration, append-only audit trails, and bridge services for REST, WebSocket, gRPC, and NTP consumers.

## Table Of Contents

- [What This Project Is](#what-this-project-is)
- [Core Architecture](#core-architecture)
- [Security Model](#security-model)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Build](#build)
- [Test](#test)
- [Run](#run)
- [Bridge Sidecar](#bridge-sidecar)
- [APIs And Contracts](#apis-and-contracts)
- [Operations](#operations)
- [Troubleshooting](#troubleshooting)
- [Development Workflow](#development-workflow)
- [License](#license)

## What This Project Is

`Quorum Time` provides:

- Byzantine fault tolerant (BFT) time convergence from multi-source observations.
- Deterministic event processing through a single orchestration pipeline.
- Fail-closed validation for critical signatures and shared-state transitions.
- Append-only vault logging with Merkle-aware integrity paths.
- Runtime control-plane stages for mode handling, HITL gates, recovery, circuit breaking, and quarantine.
- A Python bridge sidecar exposing normalized consumption interfaces.

## Core Architecture

### Runtime Plane (Aegis)

- **`EventOrchestrator`** is the single execution spine.
- All runtime mutations must flow through `EventOrchestrator::ingest(...)`.
- Pipeline stages enforce policy and safety (passport validation, vault write, gossip handling, Merkle updates, convergence, quorum/state apply, control-plane stages).

### Data/Proof Plane

- `SignedState` protobuf envelopes carry event payload, gossip metadata, and optional anchor proof.
- Shared-state and sync payloads are encoded/decoded through `pipeline_event_codec`.
- Signature verification uses registered authority key material (`crypto_verify`).

### Audit/Storage Plane

- `ColdVault` persists append-only logs and operational security events.
- Shared-state snapshots and authority sequence state are persisted and recoverable on startup.

## Security Model

Design principles:

- **Fail-closed first:** invalid/missing signatures, decode failures, stale versions, and policy violations reject state mutation.
- **Determinism over convenience:** canonical payload forms and strict decode behavior reduce ambiguity.
- **No silent errors:** security-relevant failures emit audit events.
- **Control-plane authorization:** runtime mode transitions happen via signed control events, not free-form payload markers.

Current posture:

- Suitable for internal environments with normal risk assumptions.
- For high-threat production environments, keep TLS/mTLS, listener readiness gates, strict config validation, and full smoke tests mandatory.

## Repository Layout

- `include/uml001/`: public headers.
- `src/core/`: core runtime, clock, orchestrator, pipeline stages.
- `src/gossip/`: dedup and convergence support.
- `src/rest/` and `rest/`: REST server/handlers.
- `proto/`: protobuf definitions (`signed_state.proto`, `clock_service.proto`).
- `bridge/`: Python bridge runtime, tests, containerization.
- `sdks/python/`: Python SDK modules.
- `spec/schemas/`: JSON Schema contracts.
- `spec/examples/canonical/`: canonical examples validated against schemas.
- `tests/`: C++ and Python validation/regression tests.
- `tools/`: helper and analysis tools.

## Prerequisites

Minimum recommended toolchain:

- C++17 compiler
- CMake 3.20+
- OpenSSL 3.x
- Protobuf + gRPC toolchain
- Python 3.14

Bridge Python minimums (aligned with generated stubs):

- `grpcio>=1.78.0`
- `grpcio-tools>=1.78.0`
- `protobuf>=6.31.1`
- `fastapi>=0.111.0`
- `uvicorn[standard]>=0.29.0`

## Build

### Core C++ Build

```bash
./build.sh
```

Or directly:

```bash
cmake -S . -B build
cmake --build build
```

### Python Extension / SDK Helpers

```bash
./build_python.sh
./build_sdk.sh
```

## Test

### C++ Test Binaries

This repo primarily produces executable test targets in `build/`.

Typical pass:

```bash
./build/test_pipeline_wiring
./build/test_shared_state_internal_event
./build/test_service_ingress_pipeline
./build/test_shared_state_route_contract
./build/test_default_gossip_provider
./build/test_bft_shared_state_schema_contract
./build/test_control_plane_stages
./build/test_schema_catalog_consistency
./build/test_gossip_security_regressions
./build/test_pipeline_codec_decode_hardening
```

### Python/Schema/Bridge Tests

```bash
python3 -m pytest tests/test_schema_validator.py -q
python3 -m pytest bridge/tests/test_config_tls_validation.py -q
python3 -m pytest bridge/tests/test_server_main_startup_invariants.py -q
python3 -m pytest bridge/tests/test_grpc_startup_smoke.py -q
```

## Run

### Main C++ Service

```bash
./build/aegis_clock_server
```

### Python Bridge

```bash
python3 -m bridge.server_main
```

Bridge process hosts:

- REST (`:8080` by default)
- WebSocket (`:8081` by default)
- gRPC (`:9090` by default)
- NTP UDP (`:1123` by default)

## Bridge Sidecar

### Local Build/Test Script

```bash
./bridge/build_bridge.sh
```

Optional image build:

```bash
./bridge/build_bridge.sh --docker
```

### Container

```bash
docker build -t yourorg/aegis-bridge:latest -f bridge/Dockerfile .
```

Notes:

- Docker image/tooling versions are pinned to satisfy generated gRPC stub/runtime requirements.
- Healthcheck uses TCP-connect style probing to avoid TLS/plaintext mismatch assumptions.

## APIs And Contracts

### gRPC

- Protos: `proto/clock_service.proto`, `bridge/bridge/proto/bridge.proto`.
- Canonical server implementation: `src/core/clock_service_impl.cpp`.

### REST

- Handler entrypoint: `src/rest/rest_handlers.cpp`.
- Shared-state route enforces strict required fields and rejects unknown fields to match schema `additionalProperties: false`.

### Schemas

- Catalog: `spec/schemas/catalog.json`.
- Key contracts include:
  - `signed_state_envelope.schema.json`
  - `event_context.schema.json`
  - `bft_shared_state.schema.json`

### Canonical Examples

- Under `spec/examples/canonical/`.
- Intended to validate machine-readable contract and runtime expectations together.

## Operations

Recommended deployment checks:

- Build succeeds (`cmake --build build`).
- C++ regression tests pass.
- Bridge startup invariants pass.
- gRPC bridge smoke test passes.
- Runtime startup logs show listeners healthy in intended mode.

Production-leaning posture:

- Use TLS/mTLS where applicable.
- Enforce bearer token and mTLS CA requirements in bridge config.
- Keep fail-closed behavior enabled for unsafe uncertain states.
- Persist vault data on durable storage.

## Troubleshooting

- **`ModuleNotFoundError: uvicorn` in bridge tests**
  - Install bridge deps in active environment:
  - `python3 -m pip install "uvicorn[standard]>=0.29.0" fastapi grpcio grpcio-tools protobuf websockets pytest pytest-asyncio httpx`

- **gRPC runtime mismatch with generated stubs**
  - Ensure `grpcio`, `grpcio-tools`, and `protobuf` meet minimums in `bridge/pyproject.toml`.

- **Bridge listener readiness failures in production mode**
  - Validate cert/key/CA paths, bearer token config, and port availability.

- **Shared-state rejected**
  - Check signature payload inputs, version monotonicity, and drift policy inputs (`warp_score` is signature-bound).

## Development Workflow

- Keep all behavioral changes routed through orchestrator pipeline semantics.
- Add/adjust tests with each security or contract change.
- Keep schema and canonical examples in sync with runtime behavior.
- Prefer fail-closed handling for parse/validation edges.
- Use focused regression tests before broad scans.

### License headers

Source files carry a consistent Apache-2.0 / copyright notice:

- C/C++: block comment (`/* ... */`).
- Python, shell, CMake, Dockerfile, YAML: `#` lines (after shebang when present).
- Protobuf: `//` lines.
- Markdown: HTML comment at the top of the file.
- JSON: root-level `"$comment"` string (schemas allow optional `"$comment"` on instances where `additionalProperties` would otherwise reject it).
- `LICENSE.md`: plain-text notice followed by the unmodified Apache 2.0 license text.

To apply or refresh headers after adding files, run:

```bash
python3 tools/apply_spdx_headers.py --dry-run   # preview
python3 tools/apply_spdx_headers.py             # write
```

The tool skips files that already contain `SPDX-License-Identifier: Apache-2.0` or the project copyright line, and skips generated protobuf outputs (`*_pb2.py`, `*.pb.h`, …) and `build/`.

## License

Apache License 2.0. See `LICENSE.md`.
