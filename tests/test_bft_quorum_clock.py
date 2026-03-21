import hashlib
import hmac as hmac_mod
import os
import time
import pytest

# Import the actual bound objects
from uml001._uml001 import (
    TimeObservation, BftClockConfig, BFTQuorumTrustedClock,
    OsStrongClock, SimpleHashProvider, SimpleFileVaultBackend,
    ColdVault, ColdVaultConfig, register_hmac_authority
)

# ---------------------------------------------------------------------------
# Constants & Global Setup
# ---------------------------------------------------------------------------
SECRET_KEY  = "test-hmac-key"
KEY_ID      = "v1"
AUTHORITIES = {"ntp1.test", "ntp2.test", "ntp3.test", "ntp4.test"}

# Register authorities for HMAC validation in the C++ static registry
_SECRET_HEX = SECRET_KEY.encode().hex()
for _host in AUTHORITIES:
    register_hmac_authority(_host, KEY_ID, _SECRET_HEX)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def clock_setup(tmp_path):
    clock_os = OsStrongClock()
    hashp = SimpleHashProvider()
    
    cv_cfg = ColdVaultConfig()
    cv_cfg.base_directory = str(tmp_path)
    
    backend_path = os.path.join(str(tmp_path), "vault_audit.log")
    backend = SimpleFileVaultBackend(backend_path)
    
    # Initialize the vault
    vault = ColdVault(cv_cfg, backend, clock_os, hashp)
    
    # Keep C++ references alive by attaching them to the vault object
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

def test_initialization_recovery(tmp_path):
    """Verify BFT clock restores drift from ColdVault state file."""
    clock_os = OsStrongClock()
    hashp    = SimpleHashProvider()
    seed_dir = str(tmp_path / "seed")
    os.makedirs(seed_dir, exist_ok=True)
    
    cv_cfg = ColdVaultConfig()
    cv_cfg.base_directory = seed_dir

    # Seed the vault
    b1 = SimpleFileVaultBackend(os.path.join(seed_dir, "seed.log"))
    v1 = ColdVault(cv_cfg, b1, clock_os, hashp)
    v1.save_last_drift(42)

    # Recovery
    b2 = SimpleFileVaultBackend(os.path.join(seed_dir, "audit.log"))
    v2 = ColdVault(cv_cfg, b2, clock_os, hashp)
    
    assert v2.load_last_drift() == 42


def test_monotonic_output(clock_setup):
    """Verify the bound now_unix() works on the BFT clock."""
    clock, _, _ = clock_setup
    t1 = clock.now_unix()
    time.sleep(0.1)
    t2 = clock.now_unix()
    assert t2 >= t1


def test_sync_updates_vault_drift(clock_setup):
    """Verify sync returns the correct result object and updates state."""
    clock, vault, _ = clock_setup
    now = int(time.time())

    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    
    # update_and_sync returns a BftSyncResult object (via std::optional)
    result = clock.update_and_sync(obs_list, 0.0)
    
    assert result is not None
    assert result.applied_drift == 5
    assert len(result.accepted_sources) >= 3
    # Double check underlying clock state
    assert clock.get_current_drift() == 5


def test_byzantine_outlier_rejection(clock_setup):
    """Verify the BFT median logic rejects outliers and honors step limits."""
    clock, _, config = clock_setup
    now = int(time.time())
    hosts = list(AUTHORITIES)

    # 3 honest (now+20), 1 liar (now-3600)
    obs_list = []
    for i, h in enumerate(hosts):
        ts = now + 20 if i < 3 else now - 3600
        obs_list.append(create_observation(h, ts, 1))

    result = clock.update_and_sync(obs_list, 0.0)
    
    assert result is not None
    # Median is 20, but clamped by max_drift_step (10)
    assert result.applied_drift == config.max_drift_step
    assert clock.get_current_drift() == 10


def test_signature_tampering_rejection(clock_setup):
    """Verify that a single bad signature doesn't invalidate the entire quorum."""
    clock, _, _ = clock_setup
    now = int(time.time())
    obs_list = [create_observation(h, now + 5, 1) for h in AUTHORITIES]
    
    # Tamper with the first observation's signature
    obs_list[0].signature_hex = "f" * 64

    result = clock.update_and_sync(obs_list, 0.0)
    
    assert result is not None
    # Still succeeds because 3/4 are valid
    assert len(result.accepted_sources) == 3
    assert result.applied_drift == 5