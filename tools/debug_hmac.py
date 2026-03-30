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
import hmac
import hashlib
import time
import requests
from sdks.python.uml001.crypto_utils import hmac_sha256_hex

# Configuration matching your server start command
SERVER_URL = "http://localhost:8080"
KEY_ID = "v1"
SECRET_HEX = "0123456789abcdef0123456789abcdef" # Example 32-byte secret

def test_signed_observation():
    """
    Manually signs an observation and sends it to the server.
    """
    host = "pool.ntp.org"
    timestamp = int(time.time())
    sequence = 1
    
    # Construct the payload string as the server expects (hostname:timestamp:seq)
    payload = f"{host}:{timestamp}:{sequence}"
    
    # Generate the signature using your utility
    sig = hmac_sha256_hex(payload, SECRET_HEX)
    
    print(f"--- Debugging HMAC ---")
    print(f"Payload:   {payload}")
    print(f"Signature: {sig}")
    
    # Send to the server
    obs_data = {
        "observations": [{
            "server_hostname": host,
            "key_id": KEY_ID,
            "unix_seconds": timestamp,
            "signature_hex": sig,
            "sequence": sequence
        }],
        "warp_score": 0.0
    }
    
    try:
        r = requests.post(f"{SERVER_URL}/time/sync", json=obs_data, headers={"X-API-Key": "supersecret"})
        print(f"Status:    {r.status_code}")
        print(f"Response:  {r.json()}")
    except Exception as e:
        print(f"Error:     {e}")

if __name__ == "__main__":
    test_signed_observation()