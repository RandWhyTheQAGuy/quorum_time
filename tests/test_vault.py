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
# tests/test_vault.py
import pytest
import os
import uml001
from pathlib import Path

@pytest.fixture
def vault_setup(tmp_path):
    tmp_dir = str(tmp_path)
    
    # 1. Create components
    clock = uml001.OsStrongClock()
    hashp = uml001.SimpleHashProvider()
    log_file = os.path.join(tmp_dir, "vault.log")
    backend = uml001.SimpleFileVaultBackend(log_file)

    # 2. Configure
    cfg = uml001.ColdVaultConfig()
    cfg.base_directory = tmp_dir 

    # 3. Instantiate
    vault = uml001.ColdVault(cfg, backend, clock, hashp)
    
    # 🛡️ ANCHOR REFERENCES (Prevents Segfault)
    vault._clock_ref = clock
    vault._hash_ref = hashp
    vault._backend_ref = backend
    
    return vault, tmp_dir