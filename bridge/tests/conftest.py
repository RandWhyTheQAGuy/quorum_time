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
"""
tests/conftest.py

Fixtures shared across all bridge tests.

Unit tests are deliberately isolated from the C++ uml001 extension:
- ClockState is real (pure Python)
- AttestedTime is real (pure Python dataclass)
- PollLoop is never instantiated in unit tests
- Integration tests that need a live BFT clock are in test_integration.py
  and are skipped unless the uml001 .so is present on PYTHONPATH
"""

from __future__ import annotations

import time
from typing import Optional

import pytest

from bridge.auth import AuthContext
from bridge.clock_state import ClockState
from bridge.config import BridgeConfig
from bridge.formats import AttestedTime


# ---------------------------------------------------------------------------
# AttestedTime factory
# ---------------------------------------------------------------------------

def make_attested_time(
    unix_seconds: float = 1_700_000_000.0,
    uncertainty_ms: float = 5.0,
    drift_ppm: float = 0.1,
    accepted_sources: Optional[list] = None,
    rejected_sources: Optional[list] = None,
    quorum_hash_hex: str = "deadbeef" * 8,
) -> AttestedTime:
    return AttestedTime(
        unix_seconds=unix_seconds,
        uncertainty_ms=uncertainty_ms,
        drift_ppm=drift_ppm,
        accepted_sources=accepted_sources or ["time.cloudflare.com", "time.google.com", "time.nist.gov"],
        rejected_sources=rejected_sources or [],
        quorum_hash_hex=quorum_hash_hex,
        local_mono_ns=time.monotonic_ns(),
    )


# ---------------------------------------------------------------------------
# ClockState fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def empty_state() -> ClockState:
    """ClockState with no data loaded."""
    return ClockState(staleness_limit_seconds=10.0)


@pytest.fixture
def populated_state() -> ClockState:
    """ClockState pre-loaded with a valid AttestedTime."""
    state = ClockState(staleness_limit_seconds=10.0)
    state.update(make_attested_time())
    return state


@pytest.fixture
def stale_state() -> ClockState:
    """ClockState loaded with data but with a very short staleness window (already expired)."""
    state = ClockState(staleness_limit_seconds=0.001)
    state.update(make_attested_time())
    time.sleep(0.01)
    return state


# ---------------------------------------------------------------------------
# Auth fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def no_auth() -> AuthContext:
    """AuthContext with auth disabled (insecure_dev=True)."""
    return AuthContext(bearer_tokens="", rate_limit_rps=1000, insecure_dev=True)


@pytest.fixture
def bearer_auth() -> AuthContext:
    """AuthContext requiring a specific bearer token."""
    return AuthContext(bearer_tokens="test-token-abc", rate_limit_rps=1000, insecure_dev=False)


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def dev_config() -> BridgeConfig:
    return BridgeConfig(
        insecure_dev=True,
        bft_fail_closed=False,
        poll_interval_seconds=0.1,
        rest_port=18080,
        ws_port=18081,
        grpc_port=19090,
        data_dir="/tmp/aegis-bridge-test",
    )
