import os
import shutil
import tempfile
import uml001


class DeterministicClock(uml001.IStrongClock):
    def __init__(self):
        self.t = 1_000_000

    def now_unix(self):
        return self.t

    def get_current_drift(self):
        return 0

    def advance(self, seconds):
        self.t += seconds


class DeterministicHash(uml001.IHashProvider):
    def sha256(self, s: str) -> str:
        return "HASH(" + s + ")"


def test_vault_security_event_logging():
    tmp = tempfile.mkdtemp()
    try:
        clock = DeterministicClock()
        hashp = DeterministicHash()
        backend = uml001.FileVaultBackend(tmp)

        vault = uml001.ColdVault(
            uml001.ColdVault.Config(tmp),
            backend,
            clock,
            hashp
        )

        vault.log_security_event("test.event", "hello")

        last = backend.read_last_line()
        assert "test.event" in last
        assert "detail=hello" in last
        assert "HASH(" in last
    finally:
        shutil.rmtree(tmp)


def test_vault_drift_persistence():
    tmp = tempfile.mkdtemp()
    try:
        clock = DeterministicClock()
        hashp = DeterministicHash()
        backend = uml001.FileVaultBackend(tmp)

        vault = uml001.ColdVault(
            uml001.ColdVault.Config(tmp),
            backend,
            clock,
            hashp
        )

        vault.save_last_drift(42)
        assert vault.load_last_drift() == 42
    finally:
        shutil.rmtree(tmp)


def test_vault_sequence_persistence():
    tmp = tempfile.mkdtemp()
    try:
        clock = DeterministicClock()
        hashp = DeterministicHash()
        backend = uml001.FileVaultBackend(tmp)

        vault = uml001.ColdVault(
            uml001.ColdVault.Config(tmp),
            backend,
            clock,
            hashp
        )

        seqs = {"srv1": 10, "srv2": 20}
        vault.save_authority_sequences(seqs)

        loaded = vault.load_authority_sequences()
        assert loaded == seqs
    finally:
        shutil.rmtree(tmp)
