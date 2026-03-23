# Quorum Time – Distributed Byzantine-Resilient Clock & Trusted Identity System

**License:** Apache 2.0  
**Repository:** [quorum_time](https://github.com/RandWhyTheQAGuy/quorum_time)  

---

## Overview

Quorum Time is a high-assurance distributed clock and identity system designed for:

- Reliable timekeeping across distributed systems
- Cryptographically verifiable timestamps
- Structured identity and capability management via Semantic Passports
- Strong auditability and policy enforcement

This repository implements a complete **Byzantine-tolerant time authority**, sidecar clients, NTP observation fetching, key rotation, vault storage, and REST API integration.

---

## Key Components

### 1. BFT Quorum Clock
- Implements a **Byzantine Fault Tolerant (BFT) clock**.
- Generates time states agreed upon by a quorum of nodes.
- Clients verify signed epochs to ensure trustworthy timestamps.
- Includes **median NTP observation aggregation** and skew correction.

### 2. Semantic Passport
- Structured identity tokens with capabilities and attributes.
- Cryptographically signed and revocable.
- Integrated with **transparency logs** for audit and forensic purposes.

### 3. Vault & Key Management
- `ColdVault`, `FileVaultBackend`, and `SimpleFileVaultBackend` for secure key storage.
- Automatic key rotation and lifecycle management.
- SHA-256 / AES-256 / HMAC support via OpenSSL bindings.

### 4. REST & Python SDK
- REST APIs for time retrieval, policy validation, and clock state queries.
- Python SDK (`client/python/uml001_client`) wraps core library functionality.
- Example scripts for **warm boot**, **skew correction**, and sidecar integration.

### 5. NTP Observation Fetcher
- Collects offsets from multiple NTP servers.
- Computes **median offset** and hashes observations for tamper-evidence.

---

## Standards Conformance

- **Byzantine Fault Tolerance (BFT)** – resilient to faulty or malicious nodes.
- **NTPv4 (RFC 5905)** – optional reference timing sources.
- **Protobuf / gRPC** – for service communication.
- **OpenSSL (FIPS 140-3 compatible crypto)** – for hashing, signing, and encryption.
- **JSON Schema / OpenAPI v3** – for configuration, payload validation, and REST API specification.
- **Apache 2.0 License** – permissive license allowing commercial and defense integration.

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

## Building the Project

### 1. Requirements
- C++17 or newer
- CMake 3.20+
- OpenSSL 3.0+
- Protobuf / gRPC
- Python 3.14 (for SDK and tests)

### 2. Build Core Library
```bash
./build.sh