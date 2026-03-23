# Quorum Time – Distributed Byzantine-Resilient Clock & Trusted Identity System

**License:** Apache 2.0  
**Repository:** [quorum_time](https://github.com/RandWhyTheQAGuy/quorum_time)

---

## Overview

Quorum Time is a high-assurance distributed clock and identity system designed for:

- Reliable timekeeping across distributed systems
- Cryptographically verifiable timestamps
- Strong auditability and policy enforcement

This repository implements a complete **Byzantine-tolerant time authority**, sidecar client, NTP observation fetcher, key rotation, vault storage, and REST API integration.

---

## Use Cases:

- Distributed control systems requiring trusted time and ordering
- Autonomous agent networks with verifiable identity and policy enforcement
- Critical logging and audit backplanes
- Defense, aerospace, and high-assurance financial systems

---

## Key Components

### 1. BFT Quorum Clock

- Implements a **Byzantine Fault Tolerant (BFT) clock**.
- Generates time states agreed upon by a quorum of nodes.
- Clients verify signed epochs to ensure trustworthy timestamps.
- Includes **median NTP observation aggregation** and skew correction.

### 2. Vault & Key Management

- `ColdVault`, `FileVaultBackend`, and `SimpleFileVaultBackend` for secure key storage.
- Automatic key rotation and lifecycle management.
- SHA-256 / AES-256 / HMAC support via OpenSSL bindings.

### 3. REST & Python SDK

- REST APIs for time retrieval, policy validation, and clock state queries.
- Python SDK (`client/python/uml001_client`) wraps core library functionality.
- Example scripts for **warm boot**, **skew correction**, and sidecar integration.

### 4. NTP Observation Fetcher

- Collects offsets from **multiple NTP servers**.
- Computes **median offset** and hashes observations for tamper-evidence.

---

## Deployment Architecture

Quorum Time operates on the principle of Byzantine Fault Tolerance (BFT). To maintain a trusted state, the system requires a specific node count based on the number of tolerated failures ($f$):

- **Minimum Nodes:** $3f + 1$ (e.g., to tolerate 1 malicious/failed node, you must deploy at least 4 nodes).
- **Consensus Threshold:** A quorum of $2f + 1$ nodes must sign a time epoch before it is considered "Trusted."
- **Discovery:** Nodes identify peers via a local `peers.json` configuration or a gRPC-based discovery service.

---

## Project Structure

- `src/core` – C++ implementations:
  - `bft_quorum_clock.cpp/h`
  - `ntp_observation_fetcher.cpp/h`
  - `vault_logger.cpp`
  - `key_rotation_manager.cpp`
  - `simple_file_vault_backend.cpp`
- `include/uml001` – core headers for integration
- `client/python` – Python SDK
- `rest/` – REST server and handler implementations
- `spec/schemas/` – JSON schema definitions for configs and payloads
- `tests/` – Unit and integration tests
- `tools/` – Debug and helper scripts

---

## Configuration

The system is configured via JSON. A standard node requires a `config.json` defining its role, vault location, and peer list:

``` json
{
  "node_id": "node-alpha-01",
  "bind_address": "0.0.0.0:8080",
  "vault": {
    "type": "file",
    "path": "/etc/quorum/vault.dat"
  },
  "ntp_sources": ["pool.ntp.org", "time.google.com"],
  "peers": [
    {"id": "node-beta-02", "address": "10.0.0.5:8080"},
    {"id": "node-gamma-03", "address": "10.0.0.6:8080"}
  ]
}
```

---

## Building the Project

### 1. Requirements

- C++17 or newer
- CMake 3.20+
- OpenSSL 3.0+
- Protobuf / gRPC
- Python 3.14 (for SDK and tests)

### 2. Build Core Library

```./build.sh```

### 3. Build Python SDK

```./build_python.sh```

### 4. Build Full SDK

```./build_sdk.sh```

### 5. Running Tests

```pytest tests/```

---

## Usage Examples:

### Python: Fetch Trusted Time:

``` python
from client.python.uml001_client import QuorumClockClient

client = QuorumClockClient("http://localhost:8080")
time_state = client.get_trusted_time()
print(time_state)
```

### C++: Fetch NTP Observation:

``` c++
#include "uml001/ntp_observation_fetcher.h"

std::vector<std::string> servers = {"pool.ntp.org", "time.google.com"};
uml001::NtpObservationFetcher fetcher(servers);
auto obs = fetcher.fetch_observation();
std::cout << "Median offset: " << obs.median_offset << std::endl;
```

### Sidecar Warm Boot:

``` python
python example_warm_boot.py
```

## System Integration Notes :

- Impact: Running Quorum Clock requires quorum nodes; clients perform signature verification for each epoch.
- Vault Management: Persistent storage required for keys and transparency logs; supports file and HSM backends.
- Network: gRPC and REST endpoints require secure transport (TLS recommended).
- Audit: All timestamps and identity claims are verifiable and tied to cryptographic proofs.

## Contributing:

- Fork the repo and clone locally.
- Follow coding standards (C++17, clang-format).
- Write tests in tests/ and ensure coverage.
- Submit pull requests with a detailed description and rationale.

---

## License:

### This project is licensed under Apache License 2.0:

- Allows commercial and defense use
- Permits modification and redistribution
- Requires preservation of license and attribution

## Standards Conformance

### NTPv4

Time synchronization protocol for distributed systems
- https://www.rfc-editor.org/rfc/rfc5905.html

### gRPC

Remote Procedure Call framework
- https://grpc.io/

### JSON Schema

Data structure validation and definition
- https://json-schema.org/specification.html

### OpenAPI v3

API specification format for REST services
- https://spec.openapis.org/oas/v3.1.1.html

### Cryptography (OpenSSL / FIPS)

Standard hashes (SHA‑256), encryption (AES‑256)
- https://www.openssl.org/

### Apache License 2.0

Permissive open‑source license
- https://www.apache.org/licenses/LICENSE-2.0

## Security Standards Conformance:

### SHA-256 (Secure Hash Standard)

Provides the cryptographic foundation for all identifiers and integrity checks within the protocol.
- https://csrc.nist.gov/publications/detail/fips/180/4/final

### Binary Merkle Tree (RFC 6962 inspired)

Used in the TransparencyLog to provide verifiable, append-only integrity for all security events.
- https://datatracker.ietf.org/doc/html/rfc6962


### Multi-Party Authorization (MPA)

Enforced by the MultiPartyRevocationController, requiring a consensus threshold of independent approvals before a security credential is invalidated.
- https://csrc.nist.gov/publications/detail/sp/800-204d/final

### Byzantine Fault Tolerance (BFT)

The consensus model used by the Quorum Clock to maintain a trusted temporal reference in environments where nodes may be compromised or malicious.
- https://lamport.azurewebsites.net/pubs/byz.pdf
