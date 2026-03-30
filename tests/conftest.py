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
import pytest
import subprocess
import time
import socket
import os

def wait_for_server(host="127.0.0.1", port=50051, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.5)
    return False

@pytest.fixture(scope="session", autouse=True)
def run_test_server():
    # 1. Clean up old test data before starting
    test_data_dir = "./test_data"
    if not os.path.exists(test_data_dir):
        os.makedirs(test_data_dir)
    
    env = os.environ.copy()
    env["AEGIS_DATA_DIR"] = test_data_dir

    # 2. Start the process
    proc = subprocess.Popen(
        ["./build/aegis_clock_server", "--data-dir", test_data_dir, "--insecure-dev"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env
    )

    # 3. Wait with a slightly longer timeout for macOS
    if not wait_for_server(timeout=10):
        # Capture logs to see why it failed
        stdout, stderr = proc.communicate(timeout=1)
        proc.terminate()
        raise RuntimeError(f"Server failed to start.\nSTDOUT: {stdout}\nSTDERR: {stderr}")

    yield proc

    # 4. Shutdown
    proc.terminate()
    proc.wait()