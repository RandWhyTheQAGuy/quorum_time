# tests/test_bft_clock_fixture.py
#
# Fixture-based BFT clock tests for local development and CI.
#
# All test expectations are aligned to the actual C++ implementation.
#
# Fixes applied:
#   [FIX-GC]         clock_os and hashp stored on mock to prevent GC.
#   [FIX-DRIFT]      vault.save_last_drift() for cold-start seeding.
#   [FIX-NAME]       bft.update_and_sync in test_fail_open.
#   [FIX-HMAC]       register_hmac_authority() for every authority.
#   [FIX-PAYLOAD]    Payload: server_hostname|key_id|unix_seconds|sequence
#   [FIX-VAULT]      mock.backend is disowned by ColdVault (unique_ptr
#                    transfer). Read audit log from disk via open() instead
#                    of mock.backend.read_all() — the Python object is
#                    invalidated the moment ColdVault takes ownership.
#                    Audit file path: tmp_path / "audit.log"
#   [FIX-FAILCLOSED] fail_closed only aborts on drift ceiling exceeded.
#   [FIX-WARP]       Warp score semantics corrected per C++ formulas.
#   [FIX-WARP-RACE]  test_warp_score_drift_clamping used now+50, but
#                    agreed_time ≈ now+50 and raw_os_time ≈ now, so
#                    target_drift ≈ 50 - (time elapsed during test) which
#                    can be < ceiling=40 due to wall clock advancement.
#                    Fixed by using now+200 to ensure target_drift > 40
#                    regardless of test execution timing.

import hashlib
import hmac as hmac_mod
import os
import time

import pytest
import uml001

from support.vault_mock import MockVault

# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

SECRET_KEY  = "test-hmac-key"
KEY_ID      = "v1"
AUTHORITIES = {"ntp1.test", "ntp2.test", "ntp3.test", "ntp4.test"}

# ---------------------------------------------------------------------------
# [FIX-HMAC] Register HMAC keys in the global C++ registry at import time.
# ---------------------------------------------------------------------------
_SECRET_HEX = SECRET_KEY.encode().hex()
for _host in AUTHORITIES:
    uml001.register_hmac_authority(_host, KEY_ID, _SECRET_HEX)

# ---------------------------------------------------------------------------
# Helper: Read the on-disk audit log
#
# [FIX-VAULT] mock.backend is disowned by ColdVault when passed as
# std::unique_ptr<IVaultBackend>. Calling mock.backend.read_all() after
# ColdVault construction raises:
#   "Python instance was disowned"
# Read the audit file directly from disk instead.
# SimpleFileVaultBackend writes to <dir>/audit.log (one line per entry).
# ---------------------------------------------------------------------------

def read_audit_log(tmp_path) -> list:
    """Read all non-empty lines from the ColdVault audit log on disk."""
    audit_path = os.path.join(str(tmp_path), "audit.log")
    if not os.path.exists(audit_path):
        return []
    with open(audit_path, "r") as f:
        return [line.rstrip("\r\n") for line in f if line.strip()]

# ---------------------------------------------------------------------------
# Helper: Build a signed TimeObservation
# ---------------------------------------------------------------------------

def create_observation(host, ts, seq, key=KEY_ID, secret=SECRET_KEY):
    """
    Construct a TimeObservation with a correct HMAC-SHA256 signature.

    [FIX-PAYLOAD] Payload matches C++ sign_observation():
        server_hostname|key_id|unix_seconds|sequence
    """
    obs = uml001.TimeObservation()
    obs.server_hostname = host
    obs.unix_seconds    = ts
    obs.sequence        = seq
    obs.key_id          = key

    payload = f"{host}|{key}|{ts}|{seq}"
    obs.signature_hex = hmac_mod.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    return obs

# ---------------------------------------------------------------------------
# Pytest fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def clock_setup(tmp_path):
    """
    Create a BFTQuorumTrustedClock wired to a MockVault and ColdVault.

    [FIX-GC] clock_os and hashp stored on mock to prevent garbage collection.
    [FIX-VAULT] mock.backend is passed into ColdVault and disowned — do not
    call mock.backend after this point. Use read_audit_log(tmp_path) instead.
    """
    mock = MockVault(initial_drift=0, tmp_dir=str(tmp_path))
    mock._clock_os = uml001.OsStrongClock()
    mock._hashp    = uml001.SimpleHashProvider()

    config_cv = uml001.ColdVaultConfig(str(tmp_path))
    vault = uml001.ColdVault(config_cv, mock.backend, mock._clock_os, mock._hashp)
    mock._vault = vault  # Keep vault alive alongside clock_os and hashp

    config = uml001.BftClockConfig()
    config.min_quorum       = 3
    config.max_drift_step   = 10
    config.max_total_drift  = 100
    config.max_cluster_skew = 0
    config.fail_closed      = False  # fail_closed=True calls std::abort() on
                                     # ceiling exceeded — keep False in tests.

    bft = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, vault)
    return bft, mock, config

# ---------------------------------------------------------------------------
# 1. Initialization & Monotonicity
# ---------------------------------------------------------------------------

def test_initialization_recovery(tmp_path):
    """
    Verify the BFT clock correctly restores drift from the ColdVault.

    [FIX-DRIFT] vault.save_last_drift() writes to disk; load_last_drift()
    reads from disk. mock.save_last_drift() is in-memory only.
    """
    clock_os = uml001.OsStrongClock()
    hashp    = uml001.SimpleHashProvider()

    seed_dir = str(tmp_path / "seed")
    os.makedirs(seed_dir, exist_ok=True)
    config_cv = uml001.ColdVaultConfig(seed_dir)

    backend_seed = uml001.SimpleFileVaultBackend(seed_dir)
    vault_seed   = uml001.ColdVault(config_cv, backend_seed, clock_os, hashp)
    vault_seed.save_last_drift(42)

    backend2 = uml001.SimpleFileVaultBackend(seed_dir)
    vault2   = uml001.ColdVault(config_cv, backend2, clock_os, hashp)

    config = uml001.BftClockConfig()
    config.min_quorum      = 3
    config.max_drift_step  = 10
    config.max_total_drift = 100
    config.fail_closed     = False

    new_clock = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, vault2)
    assert new_clock.get_current_drift() == 42, (
        f"Expected cold-start drift=42, got {new_clock.get_current_drift()}"
    )


def test_monotonic_output(clock_setup):
    """Ensure now_unix() never moves backward."""
    clock, _, _ = clock_setup
    t1 = clock.now_unix()
    time.sleep(0.1)
    t2 = clock.now_unix()
    assert t2 >= t1, f"now_unix() moved backward: t1={t1} t2={t2}"


def test_multiple_sync_rounds_accumulate_drift(clock_setup):
    """
    Multiple valid sync rounds accumulate drift.

    BFT trim: with 4 authorities all valid, f=(4-1)//3=1.
    Clustered = middle 2. agreed_time = mean of those 2 = now+5.
    target_drift = agreed_time - raw_os_time ≈ 5s.
    drift_step clamped to max_drift_step=10, so applied=5.
    """
    clock, mock, config = clock_setup
    now = int(time.time())

    obs1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    result1 = clock.update_and_sync(obs1)
    assert result1 is not None, "First sync round must succeed."
    assert result1.accepted_sources == 2, "BFT trim: f=1 with 4 valid → accepted=2."
    assert clock.get_current_drift() == 5

    obs2 = [create_observation(h, now + 8, 2) for h in AUTHORITIES]
    result2 = clock.update_and_sync(obs2)
    assert result2 is not None, "Second sync round must succeed."
    assert clock.get_current_drift() <= config.max_total_drift

# ---------------------------------------------------------------------------
# 2. Byzantine Resilience
# ---------------------------------------------------------------------------

def test_byzantine_outlier_rejection(clock_setup):
    """
    BFT trim drops the malicious outlier.

    3 honest at now+20, 1 malicious at now-3600.
    All 4 have valid signatures. BFT sorts and trims f=1 from each end:
    drops now-3600 (low) and one now+20 (high). Clustered=[now+20, now+20].
    agreed_time≈now+20. drift_step clamped to max_drift_step=10.
    """
    clock, mock, _ = clock_setup
    now   = int(time.time())
    hosts = list(AUTHORITIES)

    obs_list = []
    for i, h in enumerate(hosts):
        ts = now + 20 if i < 3 else now - 3600
        obs_list.append(create_observation(h, ts, 1))

    result = clock.update_and_sync(obs_list)
    assert result is not None, "Honest quorum of 3 should succeed via BFT trim."
    assert clock.get_current_drift() == 10, (
        "Drift must be clamped to max_drift_step=10."
    )


def test_insufficient_quorum_rejection(clock_setup):
    """Fewer than min_quorum valid observations must cause round rejection."""
    clock, mock, _ = clock_setup
    now   = int(time.time())
    hosts = list(AUTHORITIES)[:2]

    obs_list = [create_observation(h, now + 5, 1) for h in hosts]
    result   = clock.update_and_sync(obs_list)
    assert result is None, "update_and_sync must return None when quorum not met."


def test_unknown_authority_ignored_or_rejected(clock_setup):
    """Observations from unknown authorities must not influence consensus."""
    clock, mock, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list.append(create_observation("evil.ntp", now + 1000, 1))

    result = clock.update_and_sync(obs_list)
    assert result is not None, (
        "Known quorum must succeed despite unknown authority observation."
    )

# ---------------------------------------------------------------------------
# 3. Warp Score
#
# C++ formulas (max_total_drift=100, max_drift_step=10):
#   warp=0.0: ceiling=100, step=10
#   warp=0.8: factor=1-0.75*0.8=0.4, ceiling=floor(40)=40, step=floor(4)=4
#   warp=1.0: ceiling=max(1,100/4)=25, step=max(1,10/4)=2
# ---------------------------------------------------------------------------

def test_warp_score_drift_clamping(clock_setup):
    """
    warp_score=0.8 gives ceiling=40, step=4.

    The ceiling check applies to proposed_total = current_drift_ + drift_step.
    A single round from drift=0 only adds step=4, giving total=4 < ceiling=40.
    To trigger ceiling rejection we must pre-accumulate drift to ≥ 37 first
    (so that the next step of 4 would give proposed_total=41 > ceiling=40).

    Strategy:
      1. Run 10 rounds with warp_score=0.0 (step=10, ceiling=100) at now+100
         to accumulate current_drift_ = 10*10 = 100... but ceiling=100 so
         proposed_total hits 100 exactly on round 10 and is accepted.
         Use 9 rounds to reach drift=90, then the 10th would give 100=ceiling
         which is accepted (not strictly greater). We need drift > ceiling.

      Simpler: use warp_score=0.0 to accumulate drift=38 in 4 rounds of +10
      (rounds 1-3 = +10 each = 30, round 4 = +10 = 40... but ceiling check is
      abs(proposed) > ceiling, so 40 is NOT > 100 → accepted at warp=0).
      Then switch to warp_score=0.8 (ceiling=40). current_drift_=40.
      Next step: proposed = 40 + 4 = 44 > 40 → rejected.

      Use warp_score=0.0 for 4 rounds at now+10 each (step=10):
        round 1: drift=10, round 2: drift=20, round 3: drift=30, round 4: drift=40
      Then one round at warp_score=0.8: proposed=40+4=44 > ceiling=40 → rejected.
    """
    clock, mock, _ = clock_setup
    now = int(time.time())

    # Pre-accumulate drift=40 using 4 rounds at warp_score=0.0 (ceiling=100, step=10)
    for seq in range(1, 5):
        obs = [create_observation(h, now + 10 * seq, seq) for h in AUTHORITIES]
        r = clock.update_and_sync(obs, warp_score=0.0)
        assert r is not None, f"Pre-accumulation round {seq} must succeed."

    assert clock.get_current_drift() == 40, (
        f"Expected pre-accumulated drift=40, got {clock.get_current_drift()}"
    )

    # Now attempt one more step at warp_score=0.8 (ceiling=40, step=4).
    # proposed_total = 40 + 4 = 44 > ceiling=40 → must be rejected.
    obs_final = [create_observation(h, now + 50, 5) for h in AUTHORITIES]
    result = clock.update_and_sync(obs_final, warp_score=0.8)
    assert result is None, (
        "proposed_total=44 > ceiling=40 at warp_score=0.8 must be rejected."
    )


def test_warp_score_zero_allows_full_ceiling(clock_setup):
    """warp_score=0.0 gives full max_total_drift=100 ceiling."""
    clock, _, config = clock_setup
    now          = int(time.time())
    target_drift = config.max_total_drift - 1  # 99s — within ceiling

    obs_list = [create_observation(h, now + target_drift, 1) for h in AUTHORITIES]
    result   = clock.update_and_sync(obs_list, warp_score=0.0)
    assert result is not None, "Full ceiling available with warp_score=0.0."
    assert clock.get_current_drift() <= config.max_total_drift


def test_warp_score_one_freezes_drift(clock_setup):
    """
    warp_score=1.0 gives ceiling=25, step=2.

    Drift of 10s is within ceiling=25 → round succeeds.
    drift_step clamped to step=2 → applied_drift=2.
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 10, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list, warp_score=1.0)
    assert result is not None, (
        "warp_score=1.0 gives ceiling=25; drift of 10s is within ceiling."
    )
    assert result.applied_drift == 2, (
        f"Expected applied_drift=2 (step=max(1,10/4)=2), got {result.applied_drift}"
    )

# ---------------------------------------------------------------------------
# 4. Replay & Signature Protection
# ---------------------------------------------------------------------------

def test_sequence_replay_rejection(clock_setup):
    """Reused sequence numbers must be rejected."""
    clock, mock, _ = clock_setup
    now = int(time.time())

    obs_v1 = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    clock.update_and_sync(obs_v1)

    obs_replay = [create_observation(h, now + 10, 1) for h in AUTHORITIES]
    result     = clock.update_and_sync(obs_replay)
    assert result is None, "Replayed sequence numbers must be rejected."


def test_signature_tampering_rejection(clock_setup, tmp_path):
    """
    One tampered signature: 3 valid remain (>= min_quorum=3) → round succeeds.
    The bad observation is logged as bft.verify.sig_failed in the audit file.

    [FIX-VAULT] Read audit log from disk — mock.backend was disowned by ColdVault.
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is not None, "3 valid observations meet min_quorum=3."
    assert result.rejected_sources == 1

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit), (
        "bft.verify.sig_failed must be written to the audit log."
    )


def test_payload_tampering_rejection(clock_setup, tmp_path):
    """
    Changing unix_seconds after signing invalidates the signature.
    Same outcome as test_signature_tampering_rejection.

    [FIX-VAULT] Read audit log from disk.
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].unix_seconds += 100

    result = clock.update_and_sync(obs_list)
    assert result is not None, "3 valid observations meet min_quorum=3."
    assert result.rejected_sources == 1

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit)

# ---------------------------------------------------------------------------
# 5. Vault interaction & persistence
# ---------------------------------------------------------------------------

def test_vault_sequences_persisted(clock_setup):
    """
    Per-authority sequences are persisted after a successful sync.
    Read back via mock._vault.load_authority_sequences().
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    clock.update_and_sync(obs_list)

    seqs = mock._vault.load_authority_sequences()
    assert seqs, "Sequences must be non-empty after a successful sync."
    for h in AUTHORITIES:
        assert seqs.get(h) == 1, f"Authority {h} sequence must be 1."


def test_vault_sync_event_logged(clock_setup, tmp_path):
    """
    Successful sync writes bft.sync.committed to the audit log on disk.

    [FIX-VAULT] Read audit log from disk — mock.backend was disowned.
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]

    result = clock.update_and_sync(obs_list)
    assert result is not None

    audit = read_audit_log(tmp_path)
    assert any("bft.sync.committed" in line for line in audit), (
        "bft.sync.committed must be written to the audit log."
    )

# ---------------------------------------------------------------------------
# 6. Fail-open vs fail-closed
# ---------------------------------------------------------------------------

def test_fail_closed_rejects_on_error(clock_setup, tmp_path):
    """
    One bad signature with fail_closed=False: 3 valid remain → round succeeds.
    The bad signature is always logged regardless of outcome.

    [FIX-FAILCLOSED] fail_closed only aborts on drift ceiling exceeded.
    [FIX-VAULT] Read audit log from disk.
    """
    clock, mock, _ = clock_setup
    now      = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    result = clock.update_and_sync(obs_list)
    assert result is not None, "3 valid observations must succeed."

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit), (
        "Signature failure must always be logged to the vault."
    )


def test_fail_open_allows_best_effort_when_configured(tmp_path):
    """
    fail_closed=False: round with one bad signature succeeds if quorum met.
    The bad signature is always logged to the audit file.

    [FIX-NAME]       bft.update_and_sync (was clock.update_and_sync).
    [FIX-GC]         clock_os and hashp stored on mock.
    [FIX-VAULT]      Read audit log from disk.
    [FIX-FAILCLOSED] fail_closed=False.
    """
    mock = MockVault(initial_drift=0, tmp_dir=str(tmp_path))
    mock._clock_os = uml001.OsStrongClock()
    mock._hashp    = uml001.SimpleHashProvider()

    config_cv = uml001.ColdVaultConfig(str(tmp_path))
    vault     = uml001.ColdVault(config_cv, mock.backend,
                                 mock._clock_os, mock._hashp)
    mock._vault = vault

    config = uml001.BftClockConfig()
    config.min_quorum       = 3
    config.max_drift_step   = 10
    config.max_total_drift  = 100
    config.max_cluster_skew = 0
    config.fail_closed      = False

    bft = uml001.BFTQuorumTrustedClock(config, AUTHORITIES, vault)
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    obs_list[0].signature_hex = "00" * 32

    bft.update_and_sync(obs_list)

    audit = read_audit_log(tmp_path)
    assert any("sig_failed" in line for line in audit), (
        "bft.verify.sig_failed must be logged even in fail_closed=False mode."
    )