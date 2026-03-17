# tests/test_bft_clock.py
#
# Fixes applied:
#   [FIX-SUPER]    DeterministicClock/Hash call super().__init__().
#   [FIX-BACKEND]  FileVaultBackend replaced with SimpleFileVaultBackend.
#                  FileVaultBackend writes to a timestamped file inside the
#                  directory, not audit.log. SimpleFileVaultBackend writes
#                  to <dir>/audit.log and is the correct backend for tests
#                  that need read-back in the same session.
#   [FIX-CONFIG]   ColdVault.Config(tmp) → ColdVaultConfig(tmp).
#   [FIX-HMAC]     register_hmac_authority() for all authorities.
#   [FIX-SIG]      Real HMAC-SHA256 signatures via make_obs().
#   [FIX-TS]       Current timestamps, not unix_seconds=1000 (year 1970).
#   [FIX-DISOWNED] backend disowned by ColdVault — read audit from disk.
#   [FIX-GC]       make_vault returns (vault, clock, hashp) to keep C++
#                  reference targets alive. ColdVault holds IStrongClock&
#                  and IHashProvider& — GC causes SIGSEGV.

import hashlib
import hmac as hmac_mod
import os
import time

import uml001


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SECRET_KEY = "bft-clock-test-key"
KEY_ID     = "k"

def read_audit_log(directory):
    path = os.path.join(str(directory), "audit.log")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.rstrip("\r\n") for l in f if l.strip()]

def make_obs(host, ts, seq, key=KEY_ID, secret=SECRET_KEY):
    obs = uml001.TimeObservation()
    obs.server_hostname = host
    obs.key_id          = key
    obs.unix_seconds    = ts
    obs.sequence        = seq
    payload = f"{host}|{key}|{ts}|{seq}"
    obs.signature_hex = hmac_mod.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return obs


class DeterministicClock(uml001.IStrongClock):
    def __init__(self):
        super().__init__()
        self.t = 1_000_000

    def now_unix(self):
        return self.t

    def get_current_drift(self):
        return 0

    def advance(self, seconds):
        self.t += seconds


class DeterministicHash(uml001.IHashProvider):
    def __init__(self):
        super().__init__()

    def sha256(self, s: str) -> str:
        return "HASH(" + s + ")"


def make_vault(tmp):
    clock   = DeterministicClock()
    hashp   = DeterministicHash()
    # [FIX-BACKEND] SimpleFileVaultBackend writes to <dir>/audit.log.
    # FileVaultBackend writes to a timestamped file — not readable via
    # read_audit_log() which looks for audit.log.
    backend = uml001.SimpleFileVaultBackend(tmp)
    vault   = uml001.ColdVault(uml001.ColdVaultConfig(tmp), backend, clock, hashp)
    # [FIX-GC] Return clock and hashp to keep C++ references alive.
    return vault, clock, hashp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_bft_rejects_unknown_authority(tmp_path):
    secret_hex = SECRET_KEY.encode().hex()
    for h in ("srv1", "srv2"):
        uml001.register_hmac_authority(h, KEY_ID, secret_hex)

    vault, clock, hashp = make_vault(str(tmp_path))

    cfg = uml001.BftClockConfig()
    bft = uml001.BFTQuorumTrustedClock(cfg, {"srv1", "srv2"}, vault)

    obs = make_obs("evil.com", int(time.time()), 1)
    assert bft.verify_observation(obs) is False

    audit = read_audit_log(tmp_path)
    assert any("unknown_authority" in line for line in audit)


def test_bft_accepts_valid_quorum(tmp_path):
    authorities = {"srv1", "srv2", "srv3"}
    secret_hex  = SECRET_KEY.encode().hex()
    for h in authorities:
        uml001.register_hmac_authority(h, KEY_ID, secret_hex)

    vault, clock, hashp = make_vault(str(tmp_path))

    cfg = uml001.BftClockConfig(
        min_quorum=3,
        max_cluster_skew=10,
        max_drift_step=5,
        max_total_drift=100,
        fail_closed=False
    )
    bft = uml001.BFTQuorumTrustedClock(cfg, authorities, vault)

    now = int(time.time())
    obs = [make_obs(h, now + 2, 1) for h in authorities]

    result = bft.update_and_sync(obs)
    assert result is not None, "Valid quorum must succeed."

    audit = read_audit_log(tmp_path)
    assert any("sync.committed" in line for line in audit)