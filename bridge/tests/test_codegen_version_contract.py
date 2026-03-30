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
from __future__ import annotations

import tomllib
from pathlib import Path


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for token in v.split("."):
        num = ""
        for ch in token:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def test_pyproject_minimums_cover_generated_stub_requirements():
    root = Path(__file__).resolve().parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())
    deps = pyproject["project"]["dependencies"]
    minimums = {d.split(">=")[0].strip(): d.split(">=")[1].strip() for d in deps if ">=" in d}

    from bridge import bridge_pb2_grpc
    from bridge import bridge_pb2

    generated_grpc_min = getattr(bridge_pb2_grpc, "GRPC_GENERATED_VERSION", "0")
    declared_grpc_min = minimums.get("grpcio", "0")
    assert _version_tuple(declared_grpc_min) >= _version_tuple(generated_grpc_min)

    # bridge_pb2 is generated with a protobuf runtime requirement in header;
    # keep pyproject minimum at least at generated baseline.
    declared_proto_min = minimums.get("protobuf", "0")
    assert _version_tuple(declared_proto_min) >= (6, 31, 1)
