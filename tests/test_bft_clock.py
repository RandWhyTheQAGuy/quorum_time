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
import os
import pytest
import time

from uml001 import (
    OsStrongClock,
    SimpleHashProvider,
    SimpleFileVaultBackend,
    ColdVaultConfig,
    ColdVault,
    BftClockConfig,
    BFTQuorumTrustedClock,
    register_hmac_authority,
)

SECRET_KEY = "bft-clock-test-key"
KEY_ID     = "k"

# Your test suite should define this somewhere globally
AUTHORITIES = {"srv1", "srv2", "srv3"}


@pytest.fixture
def clock_setup(tmp_path):
    """
    Creates a fully initialized BFTQuorumTrustedClock + ColdVault instance
    consistent with the updated UML‑001 API.
    """

    # ------------------------------------------------------------
    # 1. Register authorities before constructing the clock
    # ------------------------------------------------------------
    secret_hex = SECRET_KEY.encode().hex()
    for host in AUTHORITIES:
        register_hmac_authority(host, KEY_ID, secret_hex)

    # ------------------------------------------------------------
    # 2. Construct vault components
    # ------------------------------------------------------------
    clock_os = OsStrongClock()
    hashp = SimpleHashProvider()

    cv_cfg = ColdVaultConfig()
    cv_cfg.base_directory = str(tmp_path)

    # The backend takes a *file path*, not a directory
    backend = SimpleFileVaultBackend(os.path.join(str(tmp_path), "vault.log"))

    vault = ColdVault(cv_cfg, backend, clock_os, hashp)

    # Anchor references to avoid GC (your pattern)
    vault._refs = [clock_os, hashp, backend]

    # ------------------------------------------------------------
    # 3. Configure BFT clock
    # ------------------------------------------------------------
    config = BftClockConfig()
    config.min_quorum = 3
    config.max_cluster_skew = 10
    config.max_drift_step = 5
    config.max_total_drift = 100
    config.fail_closed = False

    # ------------------------------------------------------------
    # 4. Construct the BFT clock
    # ------------------------------------------------------------
    clock = BFTQuorumTrustedClock(config, AUTHORITIES, vault)

    return clock, vault, config
