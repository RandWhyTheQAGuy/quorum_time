"""
uml001 – Byzantine Fault-Tolerant Trusted Clock SDK for Python
==============================================================

This package is a full Python SDK mirroring the UML-001 C++ implementation.

Modules
-------
crypto_utils
    SHA-256, HMAC-SHA-256, Ed25519, AES-256-GCM, Base64, CSPRNG, secure zero.
vault
    Append-only hash-chained audit vault with file rotation and archival.
ntp_fetcher
    Concurrent NTP query pool with HMAC-signed observations.
bft_clock
    Byzantine Fault-Tolerant quorum clock with drift correction,
    monotonic guarantee, and formal PBFT trimming.
sync_daemon
    Background sync loop with shared-store coordination (in-memory or Redis).

Quick start
-----------
::

    from uml001 import (
        BFTQuorumTrustedClock, BFTClockConfig,
        ColdVault, VaultConfig,
        NtpObservationFetcher, NtpServerEntry,
        BFTSyncDaemon, InMemorySharedStore,
        register_hmac_authority, generate_random_bytes_hex,
    )

    hmac_key = generate_random_bytes_hex(32)

    authorities = {
        "time.cloudflare.com", "time.google.com",
        "time.windows.com", "time.apple.com", "time.nist.gov",
    }
    for host in authorities:
        register_hmac_authority(host, hmac_key)

    vault = ColdVault(VaultConfig(base_directory="var/uml001/vault"))
    fetcher = NtpObservationFetcher(hmac_key)
    clock = BFTQuorumTrustedClock(BFTClockConfig(), authorities, vault)

    store = InMemorySharedStore()
    daemon = BFTSyncDaemon(clock, fetcher, vault, store)
    daemon.start()

    # Use BFT-verified time anywhere in your application:
    now = clock.now_unix()

    daemon.stop()
"""

from .crypto_utils import (
    sha256_raw,
    sha256_hex,
    hmac_sha256_hex,
    secure_random_bytes,
    generate_random_bytes_hex,
    constant_time_equals,
    base64_encode,
    base64_decode,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    ed25519_sign_hex,
    ed25519_verify_hex,
    AESGCMResult,
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
    secure_zero,
)

from .vault import (
    VaultConfig,
    IVaultBackend,
    FileVaultBackend,
    ColdVault,
)

from .ntp_fetcher import (
    NtpServerEntry,
    NtpObservation,
    TimeObservation,
    NtpObservationFetcher,
)

from .bft_clock import (
    BFTClockConfig,
    BftSyncResult,
    BFTQuorumTrustedClock,
    register_hmac_authority,
    clear_authority_registry,
    crypto_verify,
)

from .sync_daemon import (
    SharedClockState,
    ISharedClockStore,
    InMemorySharedStore,
    RedisSharedStore,
    BFTSyncDaemon,
)

__all__ = [
    # crypto_utils
    "sha256_raw", "sha256_hex", "hmac_sha256_hex",
    "secure_random_bytes", "generate_random_bytes_hex",
    "constant_time_equals",
    "base64_encode", "base64_decode",
    "ed25519_generate_keypair", "ed25519_sign", "ed25519_verify",
    "ed25519_sign_hex", "ed25519_verify_hex",
    "AESGCMResult", "aes256_gcm_encrypt", "aes256_gcm_decrypt",
    "secure_zero",
    # vault
    "VaultConfig", "IVaultBackend", "FileVaultBackend", "ColdVault",
    # ntp_fetcher
    "NtpServerEntry", "NtpObservation", "TimeObservation",
    "NtpObservationFetcher",
    # bft_clock
    "BFTClockConfig", "BftSyncResult", "BFTQuorumTrustedClock",
    "register_hmac_authority", "clear_authority_registry", "crypto_verify",
    # sync_daemon
    "SharedClockState", "ISharedClockStore", "InMemorySharedStore",
    "RedisSharedStore", "BFTSyncDaemon",
]

__version__ = "1.0.0"
