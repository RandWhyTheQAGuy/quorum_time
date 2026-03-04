## Quorum Time - Secure Time Platform

Quorum Time provides an open source secure, verifiable, and Byzantine‑fault‑tolerant time synchronization system for distributed environments. It combines authenticated NTP observations, tamper‑evident storage, and quorum‑based time agreement to deliver a trusted, monotonic timeline suitable for security‑critical and multi‑region deployments.

## Key Features

- Authenticated NTP observations using HMAC‑SHA256 or Ed25519 signatures

- Byzantine‑fault‑tolerant quorum clock with outlier trimming and skew enforcement

- Tamper‑evident vault for sync events, drift values, and authority sequences

- Replay protection via per‑authority sequence numbers and persistent state

- AES‑256‑GCM encryption for secure storage and transport of sensitive data

- Monotonic, drift‑controlled time with configurable ceilings and fail‑closed modes

- Sync daemon for periodic updates and cluster‑wide state adoption

- Comprehensive test suite mirroring C++ security invariants

## Architecture Overview

### Cryptographic Layer

Implements hashing, HMAC, Ed25519 signatures, AES‑GCM encryption, secure randomness, and constant‑time comparison. These primitives form the trust boundary for all higher‑level components.

### Vault Layer

Provides append‑only, tamper‑evident logs of synchronization events. Detects modification through chain verification and persists authority sequence numbers to prevent replay attacks.

### NTP Fetcher

Authenticates and sequences NTP observations from trusted authorities. Supports state save/load for continuity across restarts.

### BFT Trusted Clock

Aggregates observations from multiple authorities, rejects outliers, enforces skew limits, and computes a consensus time. Persists drift and sequence state to the vault.

### Sync Daemon

Coordinates periodic sync cycles, adopts peer state when beneficial, and monitors for stale or degraded conditions.

## Getting Started

- Install dependencies

```
bash
  
pip install -r requirements.txt
```

- Run the test suite

```
bash
  
pytest -q
```

- Basic usage example

```
python
  
from uml001 import BFTQuorumTrustedClock, BFTClockConfig  
from uml001.vault import ColdVault, VaultConfig
vault = ColdVault(VaultConfig(base_directory="./vault"))
  
clock = BFTQuorumTrustedClock(BFTClockConfig(), authorities, vault)

now = clock.now_unix()
print("Trusted time:", now)`
```

## Contributing

Contributions in the following areas are most welcome:

- New authority backends

- Alternative vault implementations

- Language bindings

- Performance improvements

- Observability and tooling

- Formal verification and audits
