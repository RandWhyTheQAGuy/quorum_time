# tests/test_vault.py
#
# Fixes applied:
#   [FIX-SUPER]    DeterministicClock/Hash call super().__init__().
#   [FIX-BACKEND]  FileVaultBackend replaced with SimpleFileVaultBackend.
#                  FileVaultBackend writes to a timestamped file, not
#                  audit.log. SimpleFileVaultBackend writes to <dir>/audit.log
#                  and is the correct backend for tests needing read-back.
#   [FIX-CONFIG]   ColdVault.Config(tmp) → ColdVaultConfig(tmp).
#   [FIX-DISOWNED] backend disowned after ColdVault construction — read
#                  audit log from disk instead of backend.read_last_line().
#   [FIX-GC]       clock and hashp kept alive via local variables that
#                  outlive the vault. ColdVault holds raw C++ references —
#                  GC causes SIGSEGV.

import os
import shutil
import tempfile
import uml001


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


def read_audit_log(directory):
    path = os.path.join(directory, "audit.log")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [l.rstrip("\r\n") for l in f if l.strip()]


def test_vault_security_event_logging():
    tmp = tempfile.mkdtemp()
    try:
        clock   = DeterministicClock()    # [FIX-GC]
        hashp   = DeterministicHash()
        # [FIX-BACKEND] SimpleFileVaultBackend writes to audit.log.
        backend = uml001.SimpleFileVaultBackend(tmp)
        vault   = uml001.ColdVault(uml001.ColdVaultConfig(tmp), backend, clock, hashp)

        vault.log_security_event("test.event", "hello")

        audit = read_audit_log(tmp)       # [FIX-DISOWNED]
        assert any("test.event" in line for line in audit), (
            f"Expected 'test.event' in audit. Lines: {audit}"
        )
        assert any("hello" in line for line in audit)

        _ = clock, hashp                  # prevent premature GC
    finally:
        shutil.rmtree(tmp)


def test_vault_drift_persistence():
    tmp = tempfile.mkdtemp()
    try:
        clock   = DeterministicClock()
        hashp   = DeterministicHash()
        backend = uml001.SimpleFileVaultBackend(tmp)
        vault   = uml001.ColdVault(uml001.ColdVaultConfig(tmp), backend, clock, hashp)

        vault.save_last_drift(42)
        assert vault.load_last_drift() == 42

        _ = clock, hashp
    finally:
        shutil.rmtree(tmp)


def test_vault_sequence_persistence():
    tmp = tempfile.mkdtemp()
    try:
        clock   = DeterministicClock()
        hashp   = DeterministicHash()
        backend = uml001.SimpleFileVaultBackend(tmp)
        vault   = uml001.ColdVault(uml001.ColdVaultConfig(tmp), backend, clock, hashp)

        seqs = {"srv1": 10, "srv2": 20}
        vault.save_authority_sequences(seqs)
        loaded = vault.load_authority_sequences()
        assert loaded == seqs

        _ = clock, hashp
    finally:
        shutil.rmtree(tmp)