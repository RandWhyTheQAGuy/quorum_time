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
import time
from unittest.mock import MagicMock
from uml001 import TimeObservation, hmac_sha256_hex

def create_mock_fetcher(hmac_key_hex, hosts, start_time=None):
    """
    Creates a mock NtpObservationFetcher that returns valid-looking 
    signed observations for a list of hosts.
    """
    mock = MagicMock()
    
    # Default to current time if not provided
    current_unix = start_time if start_time else int(time.time())
    
    def side_effect_fetch():
        observations = []
        for i, host in enumerate(hosts):
            # Simulate slight variance in arrival/server time
            ts = current_unix + (i % 2) 
            seq = 1
            payload = f"{host}:{ts}:{seq}"
            sig = hmac_sha256_hex(payload, hmac_key_hex)
            
            observations.append(TimeObservation(
                server_hostname=host,
                key_id="v1",
                unix_seconds=ts,
                signature_hex=sig,
                sequence=seq
            ))
        return observations

    mock.fetch.side_effect = side_effect_fetch
    return mock

def test_bft_with_mock():
    """Example of how to use the mock in a BFT test."""
    key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    hosts = ["time.apple.com", "time.google.com", "time.cloudflare.com"]
    
    # 1. Setup mock
    mock_fetcher = create_mock_fetcher(key, hosts)
    
    # 2. Act
    observations = mock_fetcher.fetch()
    
    # 3. Assert
    assert len(observations) == 3
    assert observations[0].server_hostname == "time.apple.com"
    assert len(observations[0].signature_hex) == 64