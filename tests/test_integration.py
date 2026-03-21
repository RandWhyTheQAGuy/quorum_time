import hashlib
import hmac as hmac_mod
import os
import shutil
import tempfile
import time
import pytest

import uml001

# ---------------------------------------------------------------------------
# HMAC helper — Matches C++ verify_observation() payload:
#   server_hostname|key_id|unix_seconds|sequence
# ---------------------------------------------------------------------------

SECRET_KEY = "integration-test-key"
KEY_ID     = "k1"

def make_observation(hostname, unix_seconds, sequence,
                     secret=SECRET_KEY, key_id=KEY_ID):
    """Build a TimeObservation with a valid HMAC-SHA256 signature."""
    payload = f"{hostname}|{key_id}|{unix_seconds}|{sequence}"

    sig_hex = hmac_mod.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()

    # Construct bound object using attribute assignment
    obs = uml001.TimeObservation() 
    obs.server_hostname = hostname
    obs.key_id = key_id
    obs.unix_seconds = unix_seconds
    obs.signature_hex = sig_hex
    obs.sequence = sequence
    
    return obs

def read_audit_log(log_path):
    """Read all non-empty lines from the specific log file."""
    if not os.path.exists(log_path):
        return []
    with open(log_path, "r") as f:
        return [line.rstrip("\r\n") for line in f if line.strip()]


def test_full_integration():
    # Temporary vault directory
    tmp_dir = tempfile.mkdtemp()
    # Explicitly define the log file path inside the temp dir
    log_file = os.path.join(tmp_dir, "audit.log")

    try:
        # 1. Register HMAC keys in the global registry (Required for C++ crypto_verify)
        authorities = ["ntp-alpha", "ntp-beta", "ntp-gamma"]
        secret_hex = SECRET_KEY.encode().hex()
        for host in authorities:
            uml001.register_hmac_authority(host, KEY_ID, secret_hex)

        # 2. Setup Components
        os_clock = uml001.OsStrongClock()
        hash_p = uml001.SimpleHashProvider()

        # FIX: Pass the specific file path to the backend, not just the directory
        backend = uml001.SimpleFileVaultBackend(log_file)
        
        vault_cfg = uml001.ColdVaultConfig()
        vault_cfg.base_directory = tmp_dir

        vault = uml001.ColdVault(vault_cfg, backend, os_clock, hash_p)

        # 3. Configure BFT Clock
        bft_cfg = uml001.BftClockConfig()
        bft_cfg.min_quorum = 3
        bft_cfg.max_total_drift = 120
        bft_cfg.fail_closed = True

        bft = uml001.BFTQuorumTrustedClock(bft_cfg, set(authorities), vault)

        # 4. Create synchronous observations
        now = int(time.time())
        observations = [
            make_observation("ntp-alpha", now + 1, 101),
            make_observation("ntp-beta",  now + 1, 101),
            make_observation("ntp-gamma", now + 1, 101),
        ]

        # 5. Run Sync
        result = bft.update_and_sync(observations, 0.0)

        assert result is not None, "BFT Sync failed to reach quorum"
        # FIX: result.accepted_sources is a list/set of hostnames, so check len()
        assert len(result.accepted_sources) == 3
        assert isinstance(result.drift_step, int)

        # 6. Verify Uncertainty Tracking
        uncertainty = bft.get_current_uncertainty()
        assert uncertainty < 2, f"Uncertainty too high after sync: {uncertainty}"

        # 7. Test Shared State Adoption (Monotonic Versioning)
        bft.apply_shared_state(
            now + 5,              # shared_agreed_time
            1,                    # shared_applied_drift
            now,                  # leader_system_time
            "dummy_sig_for_test", # signature_hex
            "leader-01",          # leader_id
            KEY_ID,               # key_id
            10,                   # monotonic_version
            0.0                   # current_warp_score
        )

        # 8. Verify Vault Persistence
        vault.save_last_drift(55)
        assert vault.load_last_drift() == 55

        # 9. Audit Log Check
        # Check the specific log_file path we defined earlier
        audit_content = read_audit_log(log_file)
        assert len(audit_content) > 0, f"No data found in {log_file}. Is the C++ logger flushing?"

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    test_full_integration()
    print("Integration test passed successfully.")