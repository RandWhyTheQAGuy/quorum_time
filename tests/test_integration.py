# tests/test_integration.py
#
# End-to-end integration test for the UML-001 Trusted Time System.
#
# All C++ components are exercised through the pybind11 bindings.
# Zero-trust objectives verified:
#   - BFT quorum clock requires >= min_quorum agreeing observations
#   - Vault audit log receives and persists a sync event
#   - Cold-start state (drift, sequences) can be written and read back
#
# Backend choice:
#   SimpleFileVaultBackend is used throughout this test. It is the
#   correct production backend for single-file append-only audit logging
#   where read-back in the same session is required. FileVaultBackend
#   is for rotation-capable multi-file deployments where the caller does
#   not need to read back through the same handle after a rotation.
#
# Fixes applied:
#   [FIX-HMAC]     register_hmac_authority() must be called for each
#                  authority before any observation is verified.
#                  crypto_verify() looks up keys from a global registry
#                  keyed by "authority_id|key_id". Without registration
#                  every verification returns false.
#   [FIX-SIG]      Observations must carry real HMAC-SHA256 signatures.
#                  signature_hex="sig" is not valid hex and will never
#                  match the computed HMAC.
#   [FIX-TS]       unix_seconds=1000 is year 1970. target_drift would be
#                  ~55 years, far exceeding max_total_drift=100. Use
#                  int(time.time()) so observations are near current time.
#   [FIX-DISOWNED] backend is disowned by ColdVault (unique_ptr transfer).
#                  Calling backend.read_last_line() after ColdVault
#                  construction raises "Python instance was disowned".
#                  Read the audit log from disk directly instead:
#                  <tmp>/audit.log written by SimpleFileVaultBackend.

import hashlib
import hmac as hmac_mod
import os
import shutil
import tempfile
import time

import uml001


# ---------------------------------------------------------------------------
# HMAC helper — same payload format as C++ sign_observation():
#   server_hostname|key_id|unix_seconds|sequence
# ---------------------------------------------------------------------------

SECRET_KEY = "integration-test-key"
KEY_ID     = "k"

def make_observation(hostname, unix_seconds, sequence,
                     secret=SECRET_KEY, key_id=KEY_ID):
    """Build a TimeObservation with a valid HMAC-SHA256 signature."""
    obs = uml001.TimeObservation()
    obs.server_hostname = hostname
    obs.key_id          = key_id
    obs.unix_seconds    = unix_seconds
    obs.sequence        = sequence

    payload = f"{hostname}|{key_id}|{unix_seconds}|{sequence}"
    obs.signature_hex = hmac_mod.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return obs


def read_audit_log(directory):
    """Read all non-empty lines from <directory>/audit.log."""
    path = os.path.join(directory, "audit.log")
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [line.rstrip("\r\n") for line in f if line.strip()]


def test_full_integration():
    # Temporary vault directory — isolated per test run
    tmp = tempfile.mkdtemp()

    try:
        # ----------------------------------------------------------
        # [FIX-HMAC] Register HMAC keys before constructing observations.
        # crypto_verify() looks up keys from the global g_hmac_keys map.
        # Must be called for every (authority_id, key_id) pair.
        # ----------------------------------------------------------
        authorities = {"srv1", "srv2", "srv3"}
        secret_hex  = SECRET_KEY.encode().hex()
        for host in authorities:
            uml001.register_hmac_authority(host, KEY_ID, secret_hex)

        # ----------------------------------------------------------
        # Construct core C++ components
        # ----------------------------------------------------------
        clock   = uml001.OsStrongClock()
        hashp   = uml001.SimpleHashProvider()
        backend = uml001.SimpleFileVaultBackend(tmp)
        config  = uml001.ColdVaultConfig(tmp)

        # ColdVault takes ownership of backend via unique_ptr.
        # [FIX-DISOWNED] Do not call backend.read_last_line() after this —
        # use read_audit_log(tmp) to inspect the on-disk audit file instead.
        vault = uml001.ColdVault(config, backend, clock, hashp)

        # ----------------------------------------------------------
        # Configure BFT quorum clock
        # ----------------------------------------------------------
        cfg = uml001.BftClockConfig()
        cfg.min_quorum       = 3
        cfg.max_cluster_skew = 10
        cfg.max_drift_step   = 5
        cfg.max_total_drift  = 100
        cfg.fail_closed      = False

        bft = uml001.BFTQuorumTrustedClock(cfg, authorities, vault)

        # ----------------------------------------------------------
        # Construct valid observations
        #
        # [FIX-TS]  Use int(time.time()) so timestamps are near current
        #           wall time. target_drift = agreed_time - raw_os_time
        #           must be within max_total_drift=100.
        # [FIX-SIG] Compute real HMAC-SHA256 signatures via make_observation().
        # ----------------------------------------------------------
        now = int(time.time())
        obs = [
            make_observation("srv1", now + 2, 1),
            make_observation("srv2", now + 2, 1),
            make_observation("srv3", now + 2, 1),
        ]

        # ----------------------------------------------------------
        # Exercise BFT sync — must produce a result
        # ----------------------------------------------------------
        result = bft.update_and_sync(obs)

        assert result is not None, (
            "update_and_sync returned None — quorum was not satisfied "
            "or BFT clock rejected all observations."
        )

        # ----------------------------------------------------------
        # Verify vault audit log received a sync event
        #
        # [FIX-DISOWNED] Read from disk — backend was disowned by ColdVault.
        # ColdVault.log_security_event("bft.sync.committed", ...) is called
        # by BFTQuorumTrustedClock.update_and_sync() on success.
        # ----------------------------------------------------------
        audit = read_audit_log(tmp)

        assert audit, (
            "Audit log is empty — vault file was not written. "
            "Check that ColdVault received the backend correctly."
        )
        assert any("bft.sync.committed" in line for line in audit), (
            f"Expected 'bft.sync.committed' in audit log. Lines found:\n"
            + "\n".join(audit)
        )

        # ----------------------------------------------------------
        # Verify cold-start state round-trip
        # ----------------------------------------------------------
        test_drift = -42
        vault.save_last_drift(test_drift)
        loaded_drift = vault.load_last_drift()

        assert loaded_drift is not None, (
            "load_last_drift returned None after save_last_drift."
        )
        assert loaded_drift == test_drift, (
            f"Drift round-trip failed: saved {test_drift}, loaded {loaded_drift}"
        )

        test_seqs = {"srv1": 10, "srv2": 20, "srv3": 30}
        vault.save_authority_sequences(test_seqs)
        loaded_seqs = vault.load_authority_sequences()

        assert loaded_seqs == test_seqs, (
            f"Sequence round-trip failed: saved {test_seqs}, loaded {loaded_seqs}"
        )

    finally:
        shutil.rmtree(tmp, ignore_errors=True)