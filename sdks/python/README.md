# uml001 – Python SDK

Byzantine Fault-Tolerant Trusted Clock SDK for Python.

Full Python port of the UML-001 C++ implementation:

| C++ file | Python module |
|---|---|
| `crypto_utils.cpp` | `uml001.crypto_utils` |
| `cold_vault.cpp` + `file_vault_backend.cpp` | `uml001.vault` |
| `ntp_observation_fetcher.cpp` | `uml001.ntp_fetcher` |
| `bft_quorum_clock.cpp` | `uml001.bft_clock` |
| `main_ntp.cpp` (sync loop + Redis) | `uml001.sync_daemon` |

## Install

```bash
pip install cryptography            # core dependency
pip install redis                   # optional: RedisSharedStore
pip install -e .                    # install SDK from source
```

## Quick start

```python
from uml001 import (
    BFTQuorumTrustedClock, BFTClockConfig,
    ColdVault, VaultConfig,
    NtpObservationFetcher,
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
daemon = BFTSyncDaemon(clock, fetcher, vault, store, sync_interval_s=60)
daemon.start()

now = clock.now_unix()   # BFT-verified Unix timestamp
print(f"BFT time: {now}")

daemon.stop()
```

## Modules

### `uml001.crypto_utils`
- `sha256_hex(data)` – SHA-256 as hex string
- `hmac_sha256_hex(payload, key_hex)` – HMAC-SHA-256 hex
- `generate_random_bytes_hex(n)` – CSPRNG hex string
- `ed25519_generate_keypair()` → `(priv_bytes, pub_bytes)`
- `ed25519_sign(private_key, message)` → 64-byte signature
- `ed25519_verify(public_key, message, signature)` → bool
- `aes256_gcm_encrypt(key, plaintext, aad)` → `AESGCMResult`
- `aes256_gcm_decrypt(key, ciphertext, nonce, tag, aad)` → bytes
- `constant_time_equals(a, b)` → bool
- `secure_zero(bytearray)` – in-place zeroisation

### `uml001.vault`
- `ColdVault` – hash-chained append-only audit log
- `FileVaultBackend` – file storage with fsync and rotation
- `VaultConfig` – size/age rotation parameters

### `uml001.ntp_fetcher`
- `NtpObservationFetcher` – concurrent NTP pool with HMAC signing
- `NtpServerEntry.default_pool()` – standard 5-server pool

### `uml001.bft_clock`
- `BFTQuorumTrustedClock` – formal PBFT trimmed quorum clock
- `BFTClockConfig` – all tunable parameters
- `register_hmac_authority(id, key_hex)` – trust an NTP authority

### `uml001.sync_daemon`
- `BFTSyncDaemon` – background sync thread with shared-store coordination
- `InMemorySharedStore` – in-process store (testing / single instance)
- `RedisSharedStore` – Redis WATCH/MULTI/EXEC optimistic-lock store

## Security properties preserved from C++

- **BFT trimming** – F = ⌊(N-1)/3⌋ outliers dropped per PBFT
- **Monotonic time** – `now_unix()` never goes backwards
- **Drift shock limit** – single-step capped at `max_drift_step`
- **Drift creep ceiling** – cumulative drift bounded by `max_total_drift`
- **Sequence replay protection** – per-authority monotonic sequences
- **Fail-closed mode** – `SystemExit` on drift ceiling breach when configured
- **Hash-chained vault** – tamper-evident log with SHA-256 chain
- **Constant-time comparison** – `hmac.compare_digest` throughout
