import pytest
import uml001
import time
import hmac
import hashlib

from support.vault_mock import MockVault

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

SECRET_KEY = "test-hmac-key"
AUTHORITIES = {"ntp1.test", "ntp2.test", "ntp3.test", "ntp4.test"}

# ---------------------------------------------------------------------------
# Helper: Build a signed TimeObservation
# ---------------------------------------------------------------------------

def create_observation(host, ts, seq, key="v1", secret=SECRET_KEY):
    """
    Construct a TimeObservation object with a simulated HMAC-SHA256 signature.

    The C++ NtpObservationFetcher signs payloads of the form:
        "<timestamp>|<hostname>|<sequence>"

    This helper reproduces that logic so the C++ BFT clock sees observations
    identical to what the real fetcher would produce.
    """
    obs = uml001.TimeObservation()
    obs.server_hostname = host
    obs.unix_seconds = ts
    obs.sequence = seq
    obs.key_id = key

    payload = f"{ts}|{host}|{seq}"
    obs.signature_hex = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return obs

# ---------------------------------------------------------------------------
# Pytest fixture: Construct a BFT clock + mock vault
# ---------------------------------------------------------------------------

@pytest.fixture
def clock_setup():
    """
    Create a BFTQuorumTrustedClock configured for a 3F+1 quorum.

    The fixture returns:
        clock  — the C++ BFT clock instance
        vault  — the Python MockVault (for inspecting logged events)
        config — the BftClockConfig used to construct the clock
    """
    vault = MockVault(initial_drift=0)

    # Wrap the Python vault in the C++ ColdVault interface.
    py_vault = uml001.ColdVault(vault)

    config = uml001.BftClockConfig()
    config.min_quorum = 3        # Require 3 of 4 authorities
    config.max_drift_step = 10   # Max drift applied per sync round
    config.max_total_drift = 100 # Max cumulative drift allowed
    config.fail_closed = True    # Reject invalid rounds

    clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, py_vault)
    return clock, vault, config

# ---------------------------------------------------------------------------
# 1. Initialization & Monotonicity
# ---------------------------------------------------------------------------

def test_initialization_recovery(clock_setup):
    """
    Verify that the BFT clock correctly restores drift from the ColdVault.
    """
    _, vault, config = clock_setup
    vault.drift = 42

    py_vault = uml001.ColdVault(vault)
    new_clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, py_vault)

    assert new_clock.get_current_drift() == 42

def test_monotonic_output(clock_setup):
    """
    Ensure now_unix() never moves backward (SEC-001).
    """
    clock, _, _ = clock_setup
    t1 = clock.now_unix()
    time.sleep(0.1)
    t2 = clock.now_unix()

    assert t2 >= t1

def test_multiple_sync_rounds_accumulate_drift(clock_setup):
    """
    Ensure that multiple valid sync rounds accumulate drift up to the ceiling.
    """
    clock, _, config = clock_setup
    now = int(time.time())

    # First round: +5s
    obs1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    clock.update_and_sync(obs1)
    assert clock.get_current_drift() == 5

    # Second round: +7s, but max_drift_step is 10, so +7 is allowed
    obs2 = [create_observation(h, now + 12, 2) for h in AUTHORITIES]
    clock.update_and_sync(obs2)
    assert clock.get_current_drift() == 12

    # Ensure we haven't exceeded max_total_drift
    assert clock.get_current_drift() <= config.max_total_drift

# ---------------------------------------------------------------------------
# 2. Byzantine Resilience (3F + 1)
# ---------------------------------------------------------------------------

def test_byzantine_outlier_rejection(clock_setup):
    """
    Test that the BFT clock rejects malicious outliers.

    Scenario:
    - 3 honest authorities report time ≈ now + 20
    - 1 malicious authority reports time ≈ now - 3600
    - min_quorum = 3, so consensus should succeed
    - Drift applied should be clamped to max_drift_step (10s)
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = []
    hosts = list(AUTHORITIES)

    for i in range(4):
        ts = now + 20 if i < 3 else now - 3600
        obs_list.append(create_observation(hosts[i], ts, 1))

    result = clock.update_and_sync(obs_list)
    assert result is not None

    assert clock.get_current_drift() == 10
    assert any(log["key"] == "bft.sync.committed" for log in vault.security_events)

def test_insufficient_quorum_rejection(clock_setup):
    """
    Ensure that fewer than min_quorum observations cause the round to be rejected.
    """
    clock, vault, config = clock_setup
    now = int(time.time())

    # Only 2 observations, but min_quorum is 3
    hosts = list(AUTHORITIES)[:2]
    obs_list = [create_observation(h, now + 5, 1) for h in hosts]

    result = clock.update_and_sync(obs_list)
    assert result is None

    # Expect a security event indicating quorum failure
    assert any("quorum_not_met" in log["key"] for log in vault.security_events)

def test_unknown_authority_ignored_or_rejected(clock_setup):
    """
    Ensure that observations from unknown authorities do not influence consensus.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    # 3 valid authorities + 1 unknown
    hosts = list(AUTHORITIES)
    obs_list = [create_observation(h, now + 5, 1) for h in hosts]
    obs_list.append(create_observation("evil.ntp", now + 1000, 1))

    result = clock.update_and_sync(obs_list)
    # Consensus should still succeed based on the known authorities
    assert result is not None
    assert any("unknown_authority" in log["key"] for log in vault.security_events)

# ---------------------------------------------------------------------------
# 3. Warp Score Drift Clamping
# ---------------------------------------------------------------------------

def test_warp_score_drift_clamping(clock_setup):
    """
    Validate that high warp scores reduce drift agility.

    With warp_score = 0.8 and max_total_drift = 100:
        allowed_drift = 20 seconds

    Attempting to push drift to 50 seconds must be rejected.
    """
    clock, vault, config = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 50, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list, warp_score=0.8)

    assert result is None
    assert any("drift_ceiling_exceeded" in log["key"] for log in vault.security_events)

def test_warp_score_zero_allows_full_ceiling(clock_setup):
    """
    With warp_score = 0.0, the full max_total_drift should be available.
    """
    clock, _, config = clock_setup
    now = int(time.time())

    # Push drift close to the ceiling in one go
    target_drift = config.max_total_drift - 1
    obs_list = [create_observation(h, now + target_drift, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list, warp_score=0.0)
    assert result is not None
    assert clock.get_current_drift() <= config.max_total_drift

def test_warp_score_one_freezes_drift(clock_setup):
    """
    With warp_score = 1.0, no additional drift should be allowed.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 10, 1) for h in AUTHORITIES]
    result = clock.update_and_sync(obs_list, warp_score=1.0)

    assert result is None
    assert any("drift_ceiling_exceeded" in log["key"] for log in vault.security_events)
    assert clock.get_current_drift() == 0

# ---------------------------------------------------------------------------
# 4. Replay & Signature Protection
# ---------------------------------------------------------------------------

def test_sequence_replay_rejection(clock_setup):
    """
    Ensure that reused sequence numbers are rejected.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    # First valid sync
    obs_v1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    clock.update_and_sync(obs_v1)

    # Replay attempt with same sequence but different timestamps
    obs_replay = [create_observation(h, now + 10, 1) for h in AUTHORITIES]
    result = clock.update_and_sync(obs_replay)

    assert result is None
    assert any("replay_detected" in log["key"] for log in vault.security_events)

def test_signature_tampering_rejection(clock_setup):
    """
    Ensure that tampered signatures cause the round to be rejected.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    # Tamper with one signature
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is None
    assert any("signature_invalid" in log["key"] for log in vault.security_events)

def test_payload_tampering_rejection(clock_setup):
    """
    Ensure that changing the payload without updating the signature is rejected.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    # Change the timestamp after signing
    obs_list[0].unix_seconds += 100

    result = clock.update_and_sync(obs_list)
    assert result is None
    assert any("signature_invalid" in log["key"] for log in vault.security_events)

# ---------------------------------------------------------------------------
# 5. Vault interaction & persistence behavior
# ---------------------------------------------------------------------------

def test_vault_sequences_persisted(clock_setup):
    """
    Ensure that per-authority sequence numbers are persisted to the vault.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    clock.update_and_sync(obs_list)

    # After a successful round, sequences should be stored
    assert vault.sequences
    for h in AUTHORITIES:
        assert vault.sequences.get(h) == 1

def test_vault_sync_event_logged(clock_setup):
    """
    Ensure that successful sync rounds log a sync event in the vault.
    """
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    result = clock.update_and_sync(obs_list)

    assert result is not None
    assert len(vault.sync_events) == 1
    event = vault.sync_events[0]
    assert "agreed_time" in event
    assert "step" in event
    assert "total_drift" in event

# ---------------------------------------------------------------------------
# 6. Fail-open vs fail-closed behavior (if supported)
# ---------------------------------------------------------------------------

def test_fail_closed_rejects_on_error(clock_setup):
    """
    With fail_closed=True, any verification or quorum error should reject the round.
    """
    clock, vault, config = clock_setup
    now = int(time.time())

    # Tamper with signatures to force an error
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is None
    assert any("signature_invalid" in log["key"] for log in vault.security_events)

def test_fail_open_allows_best_effort_when_configured(clock_setup):
    """
    With fail_closed=False, the clock may choose a best-effort time even on partial errors.

    This test assumes the implementation supports a more permissive mode.
    If not, it will still document the expected behavior.
    """
    clock, vault, config = clock_setup
    config.fail_closed = False

    now = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    # Rebuild clock with updated config
    py_vault = uml001.ColdVault(vault)
    clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, py_vault)

    result = clock.update_and_sync(obs_list)

    # Depending on implementation, this may succeed or fail; we at least assert
    # that a security event is logged documenting the degraded condition.
    assert any("signature_invalid" in log["key"] for log in vault.security_events)
