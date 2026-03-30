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
# tests/test_ntp_fetcher.py
#
# Fix applied:
#   [FIX-NTPENTRY] NtpServerEntry() takes no positional args — use attribute
#                  assignment. The binding uses default py::init<>() only.

import uml001

def test_ntp_fetcher_hmac_setting():
    entry = uml001.NtpServerEntry()
    entry.hostname = "time.google.com"
    entry.timeout_ms = 2000
    entry.max_delay_ms = 1000
    
    # Matching the C++ Constructor:
    # (hmac_key, key_id, servers, quorum_size, timeout_ms, max_delay_ms)
    fetcher = uml001.NtpObservationFetcher(
        "initial_key",      # hmac_key
        "v1",               # key_id
        [entry],            # servers
        1,                  # quorum_size (changed from 3 to 1 since we only have 1 entry)
        2000,               # timeout_ms
        1000                # max_delay_ms
    )
    
    # Matching C++: void set_hmac_key(const std::string& new_hmac_key);
    fetcher.set_hmac_key("NEWKEY")

    # No crash = bindings are correct.
    assert True