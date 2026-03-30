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
class ColdVaultMock:
    """
    Minimal Python implementation of ColdVault for pytest.
    Stores everything in memory.
    """

    def __init__(self):
        self.last_drift = None
        self.authority_sequences = {}
        self.security_events = []
        self.sync_events = []

    def load_last_drift(self):
        return self.last_drift

    def load_authority_sequences(self):
        return dict(self.authority_sequences)

    def save_authority_sequences(self, seq):
        self.authority_sequences = dict(seq)

    def log_sync_event(self, agreed_time, drift_step, total_drift):
        self.sync_events.append(
            (agreed_time, drift_step, total_drift)
        )

    def log_security_event(self, key, detail):
        self.security_events.append((key, detail))
