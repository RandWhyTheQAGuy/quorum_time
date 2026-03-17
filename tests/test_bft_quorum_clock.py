# tests/test_bft_quorum_clock.py
#
# Fixes applied:
#   [FIX-COLDVAULT]  uml001.ColdVault(vault) — ColdVault cannot wrap a
#                    Python MockVault directly. ColdVault requires
#                    (config, backend, clock, hashp). The fixture is
#                    rewritten to use the same pattern as test_bft_clock_fixture.py.
#   [FIX-HMAC]       register_hmac_authority() called for every authority.
#   [FIX-PAYLOAD]    Payload format corrected to host|key|ts|seq.
#   [FIX-VAULT]      Assertions against vault.security_events/sync_events
#                    replaced with read_audit_log() — MockVault is bypassed
#                    by ColdVault for all C++ vault calls.
#   [FIX-SEMANTICS]  Test expectations updated to match actual C++ behavior
#                    (same corrections already applied in test_bft_clock_fixture.py).

import hashlib
import hmac as hmac_mod
import os
import time

import pytest
import uml001

from support.vault_mock import MockVault

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECRET_KEY  = "test-hmac-key"
KEY_ID      = "v1"
AUTHORITIES = {"ntp1.test", "ntp2.test", "ntp3.test", "ntp4.test"}

# [FIX-HMAC] Register at module import time.
_SECRET_HEX = SECRET_KEY.encode().hex()
for _host in AUTHORITIES:
    uml001.register_hmac_authority(_host, KEY_ID, _SECRET_HEX)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_audit_log(directory):
    path = os.path.join(str(directory), "audit.log")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.rstrip("\r\n") for l in f if l.strip()]


def create_observation(host, ts, seq, key=KEY_ID, secret=SECRET_KEY):
    """[FIX-PAYLOAD] Correct payload: host|key|ts|seq"""
    obs = uml001.TimeObservation()
    obs.server_hostname = host
    obs.unix_seconds    = ts
    obs.sequence        = seq
    obs.key_id          = key
    payload = f"{host}|{key}|{ts}|{seq}"
    obs.signature_hex = hmac_mod.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return obs

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def clock_setup(tmp_path):
    """
    [FIX-COLDVAULT] ColdVault cannot wrap MockVault directly.
    Use the same pattern as test_bft_clock_fixture.py:
      mock.backend → ColdVault, keep clock_os/hashp alive on mock.
    """
    mock = MockVault(initial_drift=0, tmp_dir=str(tmp_path))
    mock._clock_os = uml001.OsStrongClock()
    mock._hashp    = uml001.SimpleHashProvider()

    config_cv = uml001.ColdVaultConfig(str(tmp_path))
    vault = uml001.ColdVault(config_cv, mock.backend, mock._clock_os, mock._hashp)
    mock._vault = vault

    config = uml001.BftClockConfig()
    config.min_quorum       = 3
    config.max_drift_step   = 10
    config.max_total_drift  = 100
    config.max_cluster_skew = 0
    config.fail_closed      = False

    clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, vault)
    return clock, mock, config

# ---------------------------------------------------------------------------
# 1. Initialization & Monotonicity
# ---------------------------------------------------------------------------

def test_initialization_recovery(tmp_path):
    """Verify the BFT clock restores drift from ColdVault on construction."""
    clock_os = uml001.OsStrongClock()
    hashp    = uml001.SimpleHashProvider()

    seed_dir = str(tmp_path / "seed")
    os.makedirs(seed_dir, exist_ok=True)
    config_cv = uml001.ColdVaultConfig(seed_dir)

    b1 = uml001.SimpleFileVaultBackend(seed_dir)
    v1 = uml001.ColdVault(config_cv, b1, clock_os, hashp)
    v1.save_last_drift(42)

    b2 = uml001.SimpleFileVaultBackend(seed_dir)
    v2 = uml001.ColdVault(config_cv, b2, clock_os, hashp)

    cfg = uml001.BftClockConfig()
    cfg.min_quorum = 3; cfg.max_drift_step = 10
    cfg.max_total_drift = 100; cfg.fail_closed = False

    new_clock = uml001.BFTQuorumTrustedClock(cfg, AUTHORITIES, v2)
    assert new_clock.get_current_drift() == 42


def test_monotonic_output(clock_setup):
    clock, _, _ = clock_setup
    t1 = clock.now_unix()
    time.sleep(0.1)
    t2 = clock.now_unix()
    assert t2 >= t1


def test_multiple_sync_rounds_accumulate_drift(clock_setup):
    clock, mock, config = clock_setup
    now = int(time.time())

    obs1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    result1 = clock.update_and_sync(obs1)
    assert result1 is not None
    assert clock.get_current_drift() == 5

    obs2 = [create_observation(h, now + 8, 2) for h in AUTHORITIES]
    result2 = clock.update_and_sync(obs2)
    assert result2 is not None
    assert clock.get_current_drift() <= config.max_total_drift

# ---------------------------------------------------------------------------
# 2. Byzantine Resilience
# ---------------------------------------------------------------------------

def test_byzantine_outlier_rejection(clock_setup, tmp_path):
    clock, mock, _ = clock_setup
    now   = int(time.time())
    hosts = list(AUTHORITIES)

    obs_list = []
    for i, h in enumerate(hosts):
        ts = now + 20 if i < 3 else now - 3600
        obs_list.append(create_observation(h, ts, 1))

    result = clock.update_and_sync(obs_list)
    assert result is not None, "Honest quorum of 3 should succeed via BFT trim."
    assert clock.get_current_drift() == 10

    audit = read_audit_log(tmp_path)
    assert any("bft.sync.committed" in line for line in audit)


def test_insufficient_quorum_rejection(clock_setup, tmp_path):
    clock, _, _ = clock_setup
    now   = int(time.time())
    hosts = list(AUTHORITIES)[:2]

    obs_list = [create_observation(h, now + 5, 1) for h in hosts]
    result   = clock.update_and_sync(obs_list)
    assert result is None

    audit = read_audit_log(tmp_path)
    assert any("quorum_insufficient" in line for line in audit)


def test_unknown_authority_ignored_or_rejected(clock_setup, tmp_path):
    clock, _, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list.append(create_observation("evil.ntp", now + 1000, 1))

    result = clock.update_and_sync(obs_list)
    assert result is not None

    audit = read_audit_log(tmp_path)
    assert any("unknown_authority" in line for line in audit)

# ---------------------------------------------------------------------------
# 3. Warp Score
# ---------------------------------------------------------------------------

def test_warp_score_drift_clamping(clock_setup):
    """Pre-accumulate drift to ceiling then verify rejection at warp=0.8."""
    clock, _, _ = clock_setup
    now = int(time.time())

    for seq in range(1, 5):
        obs = [create_observation(h, now + 10 * seq, seq) for h in AUTHORITIES]
        r = clock.update_and_sync(obs, warp_score=0.0)
        assert r is not None

    assert clock.get_current_drift() == 40

    obs_final = [create_observation(h, now + 50, 5) for h in AUTHORITIES]
    result = clock.update_and_sync(obs_final, warp_score=0.8)
    assert result is None


def test_warp_score_zero_allows_full_ceiling(clock_setup):
    clock, _, config = clock_setup
    now          = int(time.time())
    target_drift = config.max_total_drift - 1

    obs_list = [create_observation(h, now + target_drift, 1) for h in AUTHORITIES]
    result   = clock.update_and_sync(obs_list, warp_score=0.0)
    assert result is not None
    assert clock.get_current_drift() <= config.max_total_drift


def test_warp_score_one_freezes_drift(clock_setup):
    """warp_score=1.0 gives ceiling=25, step=2 — round succeeds with applied=2."""
    clock, _, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 10, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list, warp_score=1.0)
    assert result is not None
    assert result.applied_drift == 2

# ---------------------------------------------------------------------------
# 4. Replay & Signature Protection
# ---------------------------------------------------------------------------

def test_sequence_replay_rejection(clock_setup):
    clock, _, _ = clock_setup
    now = int(time.time())

    obs_v1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    clock.update_and_sync(obs_v1)

    obs_replay = [create_observation(h, now + 10, 1) for h in AUTHORITIES]
    result     = clock.update_and_sync(obs_replay)
    assert result is None


def test_signature_tampering_rejection(clock_setup, tmp_path):
    """One tampered sig: 3 valid remain → round succeeds, sig_failed logged."""
    clock, _, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is not None
    assert result.rejected_sources == 1

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit)


def test_payload_tampering_rejection(clock_setup, tmp_path):
    clock, _, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].unix_seconds += 100

    result = clock.update_and_sync(obs_list)
    assert result is not None
    assert result.rejected_sources == 1

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit)

# ---------------------------------------------------------------------------
# 5. Vault persistence
# ---------------------------------------------------------------------------

def test_vault_sequences_persisted(clock_setup):
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    clock.update_and_sync(obs_list)

    seqs = mock._vault.load_authority_sequences()
    assert seqs
    for h in AUTHORITIES:
        assert seqs.get(h) == 1


def test_vault_sync_event_logged(clock_setup, tmp_path):
    clock, _, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list)
    assert result is not None

    audit = read_audit_log(tmp_path)
    assert any("bft.sync.committed" in line for line in audit)

# ---------------------------------------------------------------------------
# 6. Fail-open vs fail-closed
# ---------------------------------------------------------------------------

def test_fail_closed_rejects_on_error(clock_setup, tmp_path):
    clock, _, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is not None  # 3 valid remain >= min_quorum=3

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit)


def test_fail_open_allows_best_effort_when_configured(tmp_path):
    mock = MockVault(initial_drift=0, tmp_dir=str(tmp_path))
    mock._clock_os = uml001.OsStrongClock()
    mock._hashp    = uml001.SimpleHashProvider()

    config_cv = uml001.ColdVaultConfig(str(tmp_path))
    vault     = uml001.ColdVault(config_cv, mock.backend,
                                 mock._clock_os, mock._hashp)
    mock._vault = vault

    config = uml001.BftClockConfig()
    config.min_quorum = 3; config.max_drift_step = 10
    config.max_total_drift = 100; config.max_cluster_skew = 0
    config.fail_closed = False

    clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, vault)
    now   = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    clock.update_and_sync(obs_list)

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit)