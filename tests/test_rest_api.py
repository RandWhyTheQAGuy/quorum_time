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
# tests/test_rest_api.py
#
# REST API tests for UML-001.
# Assumes a running server at BASE_URL with matching API key config.

import time
import pytest

from client.python.uml001_client import (
    Uml001Client,
    TimeObservation,
    SharedStateMessage,
    ApiError,
    AuthError,
)


BASE_URL = "http://localhost:8080"


def test_auth_failure():
    """
    Ensures that the server rejects requests without proper authentication.
    """
    client = Uml001Client(BASE_URL, api_key="wrong-key")

    with pytest.raises(AuthError):
        client.get_time()


def test_get_time_success():
    """
    Ensures that GET /time/now works with valid authentication.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")
    t = client.get_time()
    assert isinstance(t, int)
    assert t > 0


def test_sync_roundtrip():
    """
    Sends a synthetic observation and verifies that the server
    performs a BFT sync round successfully.

    NOTE:
    - signature_hex is intentionally fake here because the server
      is expected to run with a DummyVault or bypassed crypto_verify
      in this test environment.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")

    obs = [
        TimeObservation(
            server_hostname="pool.ntp.org",
            key_id="v1",
            unix_seconds=int(time.time()),
            signature_hex="00",
            sequence=1,
        )
    ]

    result = client.sync(obs)
    assert result.accepted_sources >= 1


def test_shared_state_adoption():
    """
    Tests the shared-state adoption path.

    SECURITY NOTE:
    - signature_hex is fake here; in production, this must be a real
      Ed25519 or TPM-backed signature.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")

    msg = SharedStateMessage(
        leader_id="leader1",
        key_id="v1",
        shared_agreed_time=int(time.time()),
        shared_applied_drift=0,
        leader_system_time_at_sync=int(time.time()),
        signature_hex="00",
        warp_score=0.0,
    )

    ok = client.apply_shared_state(msg)
    assert ok is True
