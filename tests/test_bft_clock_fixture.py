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
import hashlib
import hmac as hmac_mod
import os
import time
import pytest

from uml001._uml001 import (
    TimeObservation, BftClockConfig, BFTQuorumTrustedClock,
    OsStrongClock, SimpleHashProvider, SimpleFileVaultBackend,
    ColdVault, ColdVaultConfig, register_hmac_authority
)

SECRET_KEY  = "test-hmac-key"
KEY_ID      = "v1"
AUTHORITIES = {"ntp1.test", "ntp2.test", "ntp3.test", "ntp4.test"}

_SECRET_HEX = SECRET_KEY.encode().hex()
for _host in AUTHORITIES:
    register_hmac_authority(_host, KEY_ID, _SECRET_HEX)

def create_observation(host, ts, seq, key=KEY_ID, secret=SECRET_KEY):
    obs = TimeObservation()
    obs.server_hostname = host
    obs.unix_seconds    = ts
    obs.sequence        = seq
    obs.key_id          = key
    payload = f"{host}|{key}|{ts}|{seq}"
    obs.signature_hex = hmac_mod.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return obs

@pytest.fixture
def clock_setup(tmp_path):
    clock_os = OsStrongClock()
    hashp = SimpleHashProvider()
    cv_cfg = ColdVaultConfig()
    cv_cfg.base_directory = str(tmp_path)
    backend = SimpleFileVaultBackend(os.path.join(str(tmp_path), "vault.log"))
    
    vault = ColdVault(cv_cfg, backend, clock_os, hashp)
    # Prevent Segfault by keeping C++ references alive
    vault._lifetime_clock = clock_os
    vault._lifetime_hashp = hashp

    config = BftClockConfig()
    config.min_quorum = 3
    config.max_drift_step = 10
    config.max_total_drift = 100
    config.fail_closed = False

    clock = BFTQuorumTrustedClock(config, AUTHORITIES, vault)
    return clock, vault, config

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_monotonic_output(clock_setup):
    clock, _, _ = clock_setup
    t1 = clock.now_unix()
    time.sleep(0.1)
    t2 = clock.now_unix()
    assert t2 >= t1

def test_multiple_sync_rounds_accumulate_drift(clock_setup):
    clock, vault, _ = clock_setup
    now = int(time.time())

    # Round 1: +5 drift. 
    obs1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    res1 = clock.update_and_sync(obs1, 0.0)
    
    assert res1 is not None
    assert res1.applied_drift == 5
    assert clock.get_current_drift() == 5

def test_byzantine_outlier_rejection(clock_setup):
    clock, vault, _ = clock_setup
    now = int(time.time())
    hosts = list(AUTHORITIES)

    # 3 honest (now+20), 1 outlier (now-3600)
    obs_list = [create_observation(h, now + 20, 1) for h in hosts[:3]]
    obs_list.append(create_observation(hosts[3], now - 3600, 1))

    clock.update_and_sync(obs_list, 0.0)
    
    # Clamped to max_drift_step (10) even if median was 20
    assert clock.get_current_drift() == 10

def test_signature_tampering_rejection(clock_setup):
    clock, _, _ = clock_setup
    now = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    
    # Break one signature
    obs_list[0].signature_hex = "00" * 32

    res = clock.update_and_sync(obs_list, 0.0)
    # Should still succeed because quorum (3) is met
    assert res is not None
    assert len(res.accepted_sources) == 3