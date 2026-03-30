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

import pytest
grpc = pytest.importorskip("grpc")

from bridge.grpc_server import build_grpc_server


def test_grpc_service_registration_smoke(populated_state):
    """
    Startup smoke guard:
    - verifies build_grpc_server registers a concrete servicer
    - verifies live GetTime / GetTimeAttested RPCs do NOT return UNIMPLEMENTED
    """
    server = build_grpc_server(populated_state, 0)
    assert server is not None, "gRPC stubs unavailable; service cannot be registered"

    port = getattr(server, "_aegis_bound_port", 0)
    assert isinstance(port, int) and port > 0

    server.start()
    try:
        from bridge import bridge_pb2  # type: ignore
        from bridge import bridge_pb2_grpc  # type: ignore

        with grpc.insecure_channel(f"127.0.0.1:{port}") as channel:
            stub = bridge_pb2_grpc.BridgeTimeServiceStub(channel)
            try:
                resp = stub.GetTime(bridge_pb2.GetTimeRequest())
                assert resp.unix_seconds > 0
                attested = stub.GetTimeAttested(bridge_pb2.GetTimeRequest())
                assert attested.unix_seconds > 0
                assert len(attested.accepted_sources) > 0
                assert attested.quorum_hash != ""
            except grpc.RpcError as exc:
                msg = str(exc)
                if "Operation not permitted" in msg:
                    pytest.skip("Sandbox blocks loopback gRPC socket")
                raise
    finally:
        server.stop(grace=0)
