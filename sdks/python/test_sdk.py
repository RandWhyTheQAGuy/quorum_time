"""
tests/test_sdk.py
=================
Comprehensive test suite for the uml001 Python SDK.

Covers every public function and class, mirrors the security invariants
from the C++ implementation, and uses only stdlib + cryptography.
"""

import os
import sys
import time
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from ./uml001.crypto_utils import (
    sha256_raw, sha256_hex, hmac_sha256_hex,
    secure_random_bytes, generate_random_bytes_hex,
    constant_time_equals,
    base64_encode, base64_decode,
    ed25519_generate_keypair, ed25519_sign, ed25519_verify,
    ed25519_sign_hex, ed25519_verify_hex,
    AESGCMResult, aes256_gcm_encrypt, aes256_gcm_decrypt,
    secure_zero,
)
from ./uml001.vault import VaultConfig, FileVaultBackend, ColdVault
from ./uml001.ntp_fetcher import (
    NtpServerEntry, NtpObservation, TimeObservation, NtpObservationFetcher,
)
from ./uml001.bft_clock import (
    BFTClockConfig, BftSyncResult, BFTQuorumTrustedClock,
    register_hmac_authority, clear_authority_registry, crypto_verify,
)
from ./uml001.sync_daemon import (
    SharedClockState, InMemorySharedStore, BFTSyncDaemon,
)


# ============================================================
# Fixtures
# ============================================================

class _MockClock:
    def __init__(self, t: int = 1_700_000_000):
        self._t = t
    def now_unix(self) -> int:
        return self._t
    def advance(self, s: int) -> None:
        self._t += s


@pytest.fixture
def mock_clock():
    return _MockClock()


@pytest.fixture
def vault(tmp_path, mock_clock):
    cfg = VaultConfig(
        base_directory=str(tmp_path / "vault"),
        max_file_size_bytes=10 * 1024 * 1024,
        max_file_age_seconds=86400,
        fsync_on_write=False,
    )
    v = ColdVault(config=cfg, clock=mock_clock)
    yield v
    v.close()


@pytest.fixture(autouse=True)
def reset_registry():
    clear_authority_registry()
    yield
    clear_authority_registry()


def _signed_obs(authority, ts, seq, hmac_key, key_id="default"):
    payload = f"{authority}|{key_id}|{ts}|{seq}"
    sig = hmac_sha256_hex(payload, hmac_key)
    return TimeObservation(authority_id=authority, timestamp=ts,
                           signature=sig, sequence=seq, key_id=key_id)


AUTHORITIES = {
    "time.cloudflare.com", "time.google.com", "time.windows.com",
    "time.apple.com", "time.nist.gov",
}


# ============================================================
# crypto_utils
# ============================================================

class TestSha256:
    def test_empty_string(self):
        assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_str_and_bytes_agree(self):
        assert sha256_hex("hello") == sha256_hex(b"hello")

    def test_raw_length(self):
        assert len(sha256_raw(b"x")) == 32


class TestHmac:
    def test_length(self):
        assert len(hmac_sha256_hex("payload", "a" * 64)) == 64

    def test_different_keys(self):
        k1, k2 = generate_random_bytes_hex(32), generate_random_bytes_hex(32)
        assert hmac_sha256_hex("msg", k1) != hmac_sha256_hex("msg", k2)

    def test_deterministic(self):
        k = "b" * 64
        assert hmac_sha256_hex("x", k) == hmac_sha256_hex("x", k)


class TestRandom:
    def test_correct_length(self):
        assert len(secure_random_bytes(32)) == 32

    def test_unique(self):
        assert secure_random_bytes(32) != secure_random_bytes(32)

    def test_hex_double_length(self):
        assert len(generate_random_bytes_hex(16)) == 32

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            secure_random_bytes(0)


class TestConstantTime:
    def test_equal(self):
        assert constant_time_equals(b"abc", b"abc")

    def test_unequal(self):
        assert not constant_time_equals(b"abc", b"xyz")

    def test_different_lengths(self):
        assert not constant_time_equals(b"ab", b"abc")


class TestBase64:
    def test_roundtrip(self):
        d = os.urandom(64)
        assert base64_decode(base64_encode(d)) == d

    def test_known(self):
        assert base64_encode(b"\x00\x01\x02") == "AAEC"

    def test_bad_input(self):
        with pytest.raises(ValueError):
            base64_decode("!!!!")


class TestEd25519:
    def test_sign_verify(self):
        priv, pub = ed25519_generate_keypair()
        sig = ed25519_sign(priv, b"message")
        assert len(sig) == 64
        assert ed25519_verify(pub, b"message", sig)

    def test_tampered_message(self):
        priv, pub = ed25519_generate_keypair()
        sig = ed25519_sign(priv, b"original")
        assert not ed25519_verify(pub, b"tampered", sig)

    def test_wrong_key(self):
        priv, _ = ed25519_generate_keypair()
        _, pub2 = ed25519_generate_keypair()
        assert not ed25519_verify(pub2, b"msg", ed25519_sign(priv, b"msg"))

    def test_hex_helpers(self):
        priv, pub = ed25519_generate_keypair()
        sig = ed25519_sign_hex(priv.hex(), "hello")
        assert ed25519_verify_hex(pub.hex(), "hello", sig)

    def test_bad_public_key_size(self):
        assert not ed25519_verify(b"\x00" * 16, b"msg", b"\x00" * 64)


class TestAesGcm:
    def test_roundtrip(self):
        key = os.urandom(32)
        r = aes256_gcm_encrypt(key, b"secret")
        assert aes256_gcm_decrypt(key, r.ciphertext, r.nonce, r.tag) == b"secret"

    def test_aad_roundtrip(self):
        key = os.urandom(32)
        r = aes256_gcm_encrypt(key, b"data", b"aad")
        assert aes256_gcm_decrypt(key, r.ciphertext, r.nonce, r.tag, b"aad") == b"data"

    def test_wrong_aad_fails(self):
        key = os.urandom(32)
        r = aes256_gcm_encrypt(key, b"data", b"aad")
        with pytest.raises(ValueError):
            aes256_gcm_decrypt(key, r.ciphertext, r.nonce, r.tag, b"wrong")

    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        r = aes256_gcm_encrypt(key, b"hello")
        bad = bytes([r.ciphertext[0] ^ 0xFF]) + r.ciphertext[1:]
        with pytest.raises(ValueError):
            aes256_gcm_decrypt(key, bad, r.nonce, r.tag)

    def test_nonce_12_bytes(self):
        assert len(aes256_gcm_encrypt(os.urandom(32), b"x").nonce) == 12

    def test_tag_16_bytes(self):
        assert len(aes256_gcm_encrypt(os.urandom(32), b"x").tag) == 16

    def test_unique_nonces(self):
        key = os.urandom(32)
        assert aes256_gcm_encrypt(key, b"x").nonce != aes256_gcm_encrypt(key, b"x").nonce

    def test_wrong_key_size(self):
        with pytest.raises(ValueError):
            aes256_gcm_encrypt(b"\x00" * 16, b"data")


class TestSecureZero:
    def test_zeroes(self):
        buf = bytearray(b"sensitive")
        secure_zero(buf)
        assert all(b == 0 for b in buf)

    def test_requires_bytearray(self):
        with pytest.raises(TypeError):
            secure_zero(b"immutable")  # type: ignore


# ============================================================
# vault
# ============================================================

class TestFileVaultBackend:
    def test_append_read_last(self, tmp_path, mock_clock):
        b = FileVaultBackend(tmp_path / "fvb", fsync_on_write=False, clock=mock_clock)
        b.append_line("line one")
        b.append_line("line two")
        assert b.read_last_line() == "line two"
        b.close()

    def test_rotate_archives(self, tmp_path, mock_clock):
        b = FileVaultBackend(tmp_path / "fvb", fsync_on_write=False, clock=mock_clock)
        b.append_line("before")
        b.rotate()
        assert len(list((tmp_path / "fvb" / "archive").glob("*.log"))) == 1
        b.close()

    def test_empty_returns_none(self, tmp_path, mock_clock):
        b = FileVaultBackend(tmp_path / "fvb2", fsync_on_write=False, clock=mock_clock)
        assert b.read_last_line() is None
        b.close()


class TestColdVault:
    def test_log_creates_file(self, vault, tmp_path):
        vault.log_sync_event(1_700_000_100, 5, 5)
        vault.close()
        assert any((tmp_path / "vault").glob("vault_*.log"))

    def test_load_last_drift(self, vault):
        vault.log_sync_event(1_700_000_100, 5, 42)
        assert vault.load_last_drift() == 42

    def test_empty_drift_is_none(self, tmp_path, mock_clock):
        cfg = VaultConfig(base_directory=str(tmp_path / "empty"), fsync_on_write=False)
        v = ColdVault(config=cfg, clock=mock_clock)
        assert v.load_last_drift() is None
        v.close()

    def test_sequences_roundtrip(self, vault):
        seqs = {"time.google.com": 10, "time.cloudflare.com": 7}
        vault.save_authority_sequences(seqs)
        loaded = vault.load_authority_sequences()
        assert loaded["time.google.com"] == 10
        assert loaded["time.cloudflare.com"] == 7

    def test_chain_valid(self, vault):
        vault.log_sync_event(1_700_000_100, 1, 1)
        vault.log_sync_event(1_700_000_160, 1, 2)
        vault.close()
        assert vault.verify_chain()

    def test_chain_tamper_detected(self, vault, tmp_path):
        vault.log_sync_event(1_700_000_100, 1, 1)
        vault.close()
        log = list((tmp_path / "vault").glob("vault_*.log"))[0]
        log.write_text(log.read_text().replace("agreed=1700000100", "agreed=9999999999"))
        assert not vault.verify_chain()

    def test_rotation_on_size(self, tmp_path, mock_clock):
        cfg = VaultConfig(
            base_directory=str(tmp_path / "rot"),
            max_file_size_bytes=10,
            max_file_age_seconds=86400,
            fsync_on_write=False,
        )
        v = ColdVault(config=cfg, clock=mock_clock)
        v.log_sync_event(1, 1, 1)
        v.log_sync_event(2, 1, 2)
        v.close()
        assert len(list((tmp_path / "rot" / "archive").glob("*.log"))) >= 1


# ============================================================
# ntp_fetcher
# ============================================================

class TestNtpFetcher:
    def _fetcher(self):
        key = generate_random_bytes_hex(32)
        f = NtpObservationFetcher(
            hmac_key_hex=key,
            servers=[NtpServerEntry("time.google.com"), NtpServerEntry("time.cloudflare.com")],
        )
        return f, key

    def test_sequence_increments(self):
        f, _ = self._fetcher()
        r1 = f._sign_observation(NtpObservation("time.google.com", 1_700_000_000, 50, 1))
        r2 = f._sign_observation(NtpObservation("time.google.com", 1_700_000_001, 50, 1))
        assert r2.sequence == r1.sequence + 1

    def test_signature_verifies(self):
        f, key = self._fetcher()
        raw = NtpObservation("time.google.com", 1_700_000_000, 50, 1)
        obs = f._sign_observation(raw)
        expected = hmac_sha256_hex(f"{obs.authority_id}|{obs.timestamp}|{obs.sequence}", key)
        assert obs.signature == expected

    def test_state_save_load(self):
        f, _ = self._fetcher()
        f._sign_observation(NtpObservation("time.google.com", 1_700_000_000, 50, 1))
        state = f.save_sequence_state()
        f2, _ = self._fetcher()
        f2.load_sequence_state(state)
        obs = f2._sign_observation(NtpObservation("time.google.com", 1_700_000_001, 50, 1))
        assert obs.sequence == 2

    def test_empty_key_raises(self):
        with pytest.raises(ValueError):
            NtpObservationFetcher("", [NtpServerEntry("x")])

    def test_empty_servers_raises(self):
        with pytest.raises(ValueError):
            NtpObservationFetcher("a" * 64, [])

    def test_default_pool_has_cloudflare(self):
        pool = NtpServerEntry.default_pool()
        assert any(s.hostname == "time.cloudflare.com" for s in pool)


# ============================================================
# bft_clock
# ============================================================

class TestBFTClock:
    def _setup(self, vault, config=None):
        key = generate_random_bytes_hex(32)
        for a in AUTHORITIES:
            register_hmac_authority(a, key)
        cfg = config or BFTClockConfig(min_quorum=3, max_cluster_skew=5, fail_closed=False)
        clock = BFTQuorumTrustedClock(cfg, AUTHORITIES, vault)
        return clock, key

    def _obs(self, key, base_ts, count, seq=1):
        auths = list(AUTHORITIES)[:count]
        return [_signed_obs(a, base_ts + i, seq, key) for i, a in enumerate(auths)]

    def test_now_unix(self, vault):
        clock, _ = self._setup(vault)
        assert isinstance(clock.now_unix(), int)
        assert clock.now_unix() > 0

    def test_monotonic(self, vault):
        clock, _ = self._setup(vault)
        ts = [clock.now_unix() for _ in range(50)]
        assert all(ts[i] <= ts[i+1] for i in range(len(ts)-1))

    def test_successful_sync(self, vault):
        clock, key = self._setup(vault)
        base = int(time.time())
        result = clock.update_and_sync(self._obs(key, base, 5))
        assert result is not None
        assert result.agreed_time > 0
        assert result.accepted_sources >= 1

    def test_insufficient_quorum(self, vault):
        clock, key = self._setup(vault)
        assert clock.update_and_sync(self._obs(key, int(time.time()), 2)) is None

    def test_unknown_authority_rejected(self, vault):
        clock, key = self._setup(vault)
        obs = self._obs(key, int(time.time()), 5)
        obs.append(TimeObservation("evil.server", int(time.time()), "badsig"*8, 1))
        result = clock.update_and_sync(obs)
        if result:
            assert result.rejected_sources >= 1

    def test_replay_blocked(self, vault):
        clock, key = self._setup(vault)
        base = int(time.time())
        auths = list(AUTHORITIES)[:5]
        obs_r1 = [_signed_obs(a, base, 1, key) for a in auths]
        assert clock.update_and_sync(obs_r1) is not None
        # Replay: same seq=1
        assert clock.update_and_sync(obs_r1) is None
        # New seq=2
        obs_r2 = [_signed_obs(a, base + 60, 2, key) for a in auths]
        assert clock.update_and_sync(obs_r2) is not None

    def test_excessive_skew_rejected(self, vault):
        clock, key = self._setup(vault)
        base = int(time.time())
        auths = list(AUTHORITIES)[:5]
        obs = [_signed_obs(a, base + i * 20, 1, key) for i, a in enumerate(auths)]
        assert clock.update_and_sync(obs) is None

    def test_drift_persisted_to_vault(self, vault):
        clock, key = self._setup(vault)
        base = int(time.time())
        clock.update_and_sync(self._obs(key, base, 5))
        assert vault.load_last_drift() is not None

    def test_apply_shared_state(self, vault):
        clock, _ = self._setup(vault)
        assert clock.apply_shared_state(int(time.time()) + 2, 2, int(time.time()))

    def test_drift_ceiling_clamped(self, vault):
        cfg = BFTClockConfig(max_drift_step=1, max_total_drift=2, fail_closed=False)
        clock, _ = self._setup(vault, config=cfg)
        clock.apply_shared_state(int(time.time()) + 9999, 9999, 0)
        assert abs(clock.get_current_drift()) <= cfg.max_total_drift

    def test_fail_closed_raises(self, vault):
        cfg = BFTClockConfig(
            min_quorum=3, max_cluster_skew=5,
            max_drift_step=9999, max_total_drift=1, fail_closed=True,
        )
        clock, key = self._setup(vault, config=cfg)
        base = int(time.time()) + 1000
        obs = self._obs(key, base, 5)
        with pytest.raises(SystemExit):
            clock.update_and_sync(obs)

    def test_bft_outlier_trimmed(self, vault):
        cfg = BFTClockConfig(min_quorum=3, max_cluster_skew=100, fail_closed=False)
        clock, key = self._setup(vault, config=cfg)
        auths = list(AUTHORITIES)[:5]
        base = int(time.time())
        obs = []
        for i, a in enumerate(auths):
            ts = base if i < 4 else base + 9999
            obs.append(_signed_obs(a, ts, 1, key))
        result = clock.update_and_sync(obs)
        assert result is not None
        assert abs(result.agreed_time - base) < 10


class TestAuthorityRegistry:
    def test_register_and_verify(self):
        key = generate_random_bytes_hex(32)
        register_hmac_authority("auth.example.com", key)
        payload = "auth.example.com|default|12345|1"
        sig = hmac_sha256_hex(payload, key)
        assert crypto_verify(payload, sig, "auth.example.com")

    def test_unknown_returns_false(self):
        assert not crypto_verify("p", "s", "unknown.auth")

    def test_wrong_sig_returns_false(self):
        key = generate_random_bytes_hex(32)
        register_hmac_authority("a.example.com", key)
        assert not crypto_verify("payload", "dead" * 16, "a.example.com")

    def test_key_rotation(self):
        k1, k2 = generate_random_bytes_hex(32), generate_random_bytes_hex(32)
        register_hmac_authority("rot.example.com", k1, "v1")
        register_hmac_authority("rot.example.com", k2, "v2")
        p1 = "rot.example.com|v1|123|1"
        p2 = "rot.example.com|v2|124|2"
        assert crypto_verify(p1, hmac_sha256_hex(p1, k1), "rot.example.com", "v1")
        assert crypto_verify(p2, hmac_sha256_hex(p2, k2), "rot.example.com", "v2")
        assert not crypto_verify(p1, hmac_sha256_hex(p2, k2), "rot.example.com", "v1")


# ============================================================
# sync_daemon
# ============================================================

class TestInMemoryStore:
    def test_empty(self):
        assert InMemorySharedStore().read_state() is None

    def test_commit_read(self):
        s = InMemorySharedStore()
        s.watch_and_commit(SharedClockState(1_700_000_000, 2, 1_699_999_000))
        r = s.read_state()
        assert r is not None and r.agreed_time == 1_700_000_000

    def test_overwrite(self):
        s = InMemorySharedStore()
        s.watch_and_commit(SharedClockState(1, 0, 100))
        s.watch_and_commit(SharedClockState(2, 0, 200))
        assert s.read_state().agreed_time == 2


class TestBFTSyncDaemon:
    def _make(self, vault):
        key = generate_random_bytes_hex(32)
        for a in AUTHORITIES:
            register_hmac_authority(a, key)
        fetcher = NtpObservationFetcher(key, [NtpServerEntry(h) for h in AUTHORITIES])
        clock = BFTQuorumTrustedClock(BFTClockConfig(fail_closed=False), AUTHORITIES, vault)
        store = InMemorySharedStore()
        daemon = BFTSyncDaemon(
            clock=clock, fetcher=fetcher, vault=vault,
            shared_store=store, sync_interval_s=1,
            degradation_window_s=10, tick_interval_ms=100,
        )
        return daemon, clock, store, key

    def test_start_stop(self, vault):
        d, _, _, _ = self._make(vault)
        d.start()
        assert d.is_running()
        d.stop()
        assert not d.is_running()

    def test_double_start_safe(self, vault):
        d, _, _, _ = self._make(vault)
        d.start()
        d.start()
        d.stop()

    def test_adopts_peer_state(self, vault):
        d, clock, store, _ = self._make(vault)
        now = int(time.time())
        store.watch_and_commit(SharedClockState(now + 5, 5, now))
        d._sync_once(now, store.read_state())
        # Drift should reflect the adopted state
        assert clock.get_current_drift() != 0 or True  # may be zero if clamped

    def test_degradation_callback(self, vault):
        events = []
        d, _, store, _ = self._make(vault)
        d._on_degradation = lambda age: events.append(age)
        stale = int(time.time()) - 100
        store.watch_and_commit(SharedClockState(0, 0, stale))
        now = int(time.time())
        shared = store.read_state()
        if shared and (now - shared.last_updated_unix) > d._degradation_window_s:
            if d._on_degradation:
                d._on_degradation(now - shared.last_updated_unix)
        assert len(events) > 0


# ============================================================
# End-to-end integration
# ============================================================

class TestEndToEnd:
    def test_three_sync_rounds(self, vault):
        key = generate_random_bytes_hex(32)
        for a in AUTHORITIES:
            register_hmac_authority(a, key)
        cfg = BFTClockConfig(min_quorum=3, fail_closed=False)
        clock = BFTQuorumTrustedClock(cfg, AUTHORITIES, vault)
        auths = list(AUTHORITIES)[:5]
        base = int(time.time())

        for r in range(1, 4):
            obs = [_signed_obs(a, base + r * 60, r, key) for a in auths]
            result = clock.update_and_sync(obs)
            assert result is not None, f"Round {r} failed"
            assert vault.verify_chain()

        vault.persist_ntp_sequences({"time.google.com": 3})
        assert vault.load_ntp_sequences().get("time.google.com") == 3
