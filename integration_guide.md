<!--
  Quorum Time — Open Trusted Time & Distributed Verification Framework
  Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
  SPDX-License-Identifier: Apache-2.0

  Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
  system designed for modern distributed environments. It provides a
  cryptographically anchored notion of time that can be aligned,
  audited, and shared across domains without requiring centralized
  trust.

  This project also includes the Aegis Semantic Passport components,
  which complement Quorum Time by offering structured, verifiable
  identity and capability attestations for agents and services.

  Core capabilities:
    - BFT Quorum Time: multi-authority, tamper-evident time agreement
                       with drift bounds, authority attestation, and
                       cross-domain alignment (AlignTime).

    - Transparency Logging: append-only, hash-chained audit records
                            for time events, alignment proofs, and
                            key-rotation operations.

    - Open Integration: designed for interoperability with distributed
                        systems, security-critical infrastructure,
                        autonomous agents, and research environments.

  Quorum Time is developed as an open-source project with a focus on
  clarity, auditability, and long-term maintainability. Contributions,
  issue reports, and discussions are welcome.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0

  This implementation is intended for open research, practical
  deployment, and community-driven evolution of verifiable time and
  distributed trust standards.

-->
# QuorumTimeAdapter — Integration Guide

**Component:** `uml001::QuorumTimeAdapter`
**Header:** `include/uml001/quorum_time_adapter.h`
**Library:** `build/libuml001_core.a`
**Audience:** Lens, Aegis Passport, AegisDB, and any other C++ consumer that
needs deterministic, cryptographically-anchored time without an HTTP or
process boundary.

---

## What This Component Does

`QuorumTimeAdapter` is a thin in-process wrapper around the full uml001 BFT
core. It owns:

- A `BFTQuorumTrustedClock` — Byzantine-fault-tolerant quorum clock with
  monotonic read guarantees and drift accounting.
- An `NtpObservationFetcher` — HMAC-signed NTP queries against a configured
  server pool.
- A `ColdVault` — append-only, hash-chained audit log for every sync event
  and security exception.
- An embedded background sync thread — same logic as the `main_ntp.cpp`
  worker, no HTTP, no gRPC, no process boundary.

The three operations it exposes to callers:

| Method | Purpose |
|---|---|
| `now()` | Deterministic BFT timestamp, no event attachment |
| `anchor_event(event_id, event_hash)` | Timestamp + proof bound to a specific write |
| `verify(anchor, event_hash)` | Offline-safe proof validation |

---

## Repository Layout After Integration

```
include/
  uml001/
    quorum_time_adapter.h     <-- public header (this component)
    bft_quorum_clock.h
    ... (existing headers unchanged)

src/
  core/
    quorum_time_adapter.cpp   <-- implementation (this component)
    bft_quorum_clock.cpp
    ... (existing sources unchanged)

CMakeLists.txt                <-- one line added to uml001_core sources
```

The header belongs at `include/uml001/quorum_time_adapter.h`.
The implementation belongs at `src/core/quorum_time_adapter.cpp`.
No other existing file is modified except `CMakeLists.txt`.

---

## Build System Change

One line was added to `uml001_core` in the root `CMakeLists.txt`:

```cmake
add_library(uml001_core STATIC
    ...
    src/core/quorum_time_adapter.cpp   # <-- this line only
    ...
)
```

After this change, `libuml001_core.a` contains the adapter. Any target that
already links `uml001_core` gains access to `QuorumTimeAdapter` with no
further build changes inside the uml001 repo.

---

## Linking From a Consumer Project (Lens, Passport, AegisDB)

### Option A — CMake subdirectory (monorepo or submodule)

```cmake
# In your consumer project's CMakeLists.txt:

add_subdirectory(path/to/uml001)   # pulls in uml001_core target

add_executable(lens_server
    src/lens_main.cpp
    src/lens_write_path.cpp
    # ... other sources
)

target_link_libraries(lens_server PRIVATE uml001_core)

target_include_directories(lens_server PRIVATE
    path/to/uml001/include
)
```

### Option B — pre-built static library (CI artifact or package)

```cmake
# Point at the pre-built archive and include directory:

add_library(uml001_core STATIC IMPORTED)
set_target_properties(uml001_core PROPERTIES
    IMPORTED_LOCATION /path/to/build/libuml001_core.a
)

target_link_libraries(lens_server PRIVATE
    uml001_core
    OpenSSL::SSL
    OpenSSL::Crypto
    # libsodium, gRPC::grpc++, protobuf::libprotobuf are transitive deps
    # of uml001_core — include them here if not propagated automatically.
)

target_include_directories(lens_server PRIVATE
    /path/to/uml001/include
)
```

---

## Quickstart: Minimal Integration

```cpp
#include "uml001/quorum_time_adapter.h"
#include "uml001/crypto_utils.h"

// --- 1. Build a Config ---------------------------------------------------
//
// In production, load hmac_key from your KMS or sealed secret store.
// Never hardcode it. Generate a fresh one with:
//   uml001::generate_random_bytes_hex(32)

uml001::QuorumTimeAdapter::Config cfg;
cfg.data_dir  = "/var/lib/lens/quorum";
cfg.hmac_key  = load_hmac_key_from_secure_store();  // 64 hex chars (32 bytes)
cfg.key_id    = "v1";
cfg.min_quorum = 3;

// --- 2. Construct and start ----------------------------------------------

uml001::QuorumTimeAdapter adapter(cfg);
adapter.start();   // launches background sync thread; returns immediately

// The first sync completes within ~1-2 seconds on a healthy network.
// If you need to wait for the first successful sync before accepting
// writes, set cfg.fail_before_sync = true and poll adapter.sync_count().

// --- 3. Use at write time ------------------------------------------------

// Bare timestamp (no event binding):
auto anchor = adapter.now();
if (!anchor.is_valid) { /* handle pre-sync state */ }

// Event-bound timestamp (recommended for all Lens/AegisDB writes):
std::string event_id   = generate_write_uuid();
std::string event_hash = sha256_hex(serialize(event_payload));

auto anchor = adapter.anchor_event(event_id, event_hash);
// Store anchor.logical_time, anchor.proof, anchor.authority
// alongside the event in your storage layer.

// --- 4. Verify a stored anchor -------------------------------------------

bool ok = adapter.verify(anchor, event_hash);
// ok == true  → proof signature is valid; anchor was issued by this key.
// ok == false → tampered, replayed, or issued under a different key_id.

// --- 5. Shutdown ---------------------------------------------------------

adapter.stop();   // joins sync thread cleanly
```

---

## Integration Pattern: Lens Write Path

Lens needs a time anchor at every write boundary. The recommended pattern
is to construct a single `QuorumTimeAdapter` at application startup and
inject a pointer (or reference) into the write path component. Do not
construct a new adapter per-write — the object is expensive to initialize
and owns a live thread.

```cpp
// lens_app.cpp — application startup

#include "uml001/quorum_time_adapter.h"

class LensApp {
public:
    explicit LensApp(const AppConfig& cfg)
        : quorum_adapter_(build_quorum_config(cfg))
    {
        quorum_adapter_.start();
        write_path_ = std::make_unique<LensWritePath>(quorum_adapter_);
    }

    ~LensApp() {
        quorum_adapter_.stop();
    }

private:
    uml001::QuorumTimeAdapter quorum_adapter_;
    std::unique_ptr<LensWritePath> write_path_;
};
```

```cpp
// lens_write_path.cpp — write boundary

#include "uml001/quorum_time_adapter.h"

class LensWritePath {
public:
    explicit LensWritePath(uml001::QuorumTimeAdapter& time)
        : time_(time) {}

    WriteResult commit(const LensEvent& event) {
        // 1. Compute the event hash BEFORE anchoring.
        //    The anchor is cryptographically bound to this hash.
        const std::string event_hash = uml001::sha256_hex(event.serialize());

        // 2. Anchor the event. This is a non-blocking call — the BFT
        //    clock reads the last agreed time from the in-process object.
        const auto anchor = time_.anchor_event(event.id(), event_hash);

        if (!anchor.is_valid) {
            return WriteResult::error("BFT clock not yet synchronized");
        }

        // 3. Store anchor fields alongside the event record.
        //    Minimum required fields for later verification:
        //      - anchor.logical_time   (ordering key)
        //      - anchor.proof          (self-contained verification payload)
        //      - anchor.event_id       (ties back to the event)
        //
        //    Recommended additional fields:
        //      - anchor.drift_us       (audit / diagnostics)
        //      - anchor.uncertainty_s  (staleness indicator)
        //      - anchor.authority      (quorum membership at sync time)
        EventRecord record;
        record.event           = event;
        record.time_unix       = anchor.logical_time;
        record.time_proof      = anchor.proof;
        record.time_authority  = anchor.authority;

        return storage_.write(record);
    }

private:
    uml001::QuorumTimeAdapter& time_;
    StorageLayer storage_;
};
```

---

## Integration Pattern: Aegis Passport Issuance

Passports need a time anchor at issuance and at each endorsement. The
anchor proves when the passport was issued against a live quorum, not
just a local clock.

```cpp
#include "uml001/quorum_time_adapter.h"

PassportRecord issue_passport(
    const PassportRequest& req,
    uml001::QuorumTimeAdapter& time)
{
    // Compute a canonical hash of the passport payload.
    // Include all fields that must be bound to the issuance timestamp.
    const std::string payload_hash = uml001::sha256_hex(
        req.subject_id + "|" + req.capabilities_json + "|" + req.issuer_id);

    // Anchor to the issuance event. event_id is the passport UUID.
    const auto anchor = time.anchor_event(req.passport_uuid, payload_hash);

    PassportRecord record;
    record.uuid             = req.passport_uuid;
    record.subject_id       = req.subject_id;
    record.issued_at_unix   = anchor.logical_time;
    record.issuance_proof   = anchor.proof;     // stored for offline verification
    record.quorum_authority = anchor.authority;
    record.capabilities     = req.capabilities_json;

    return record;
}

// Verification at presentation time:
bool verify_passport_timestamp(
    const PassportRecord& record,
    uml001::QuorumTimeAdapter& time)
{
    // Reconstruct the payload hash from the stored passport fields.
    const std::string payload_hash = uml001::sha256_hex(
        record.subject_id + "|" + record.capabilities + "|" + record.issuer_id);

    // Rebuild the anchor as it would have been at issuance.
    uml001::TimeAnchor anchor;
    anchor.logical_time = record.issued_at_unix;
    anchor.proof        = record.issuance_proof;
    anchor.authority    = record.quorum_authority;
    anchor.event_id     = record.uuid;
    anchor.is_valid     = true;

    return time.verify(anchor, payload_hash);
}
```

---

## Configuration Reference

| Field | Type | Default | Notes |
|---|---|---|---|
| `data_dir` | `filesystem::path` | `./data/quorum_adapter` | Vault log directory. Must be persistent across restarts. |
| `hmac_key` | `string` | *(required)* | 64 hex chars (32 bytes). Load from KMS. |
| `key_id` | `string` | `"v1"` | Increment on key rotation. Store alongside anchors. |
| `ntp_servers` | `vector<NtpServerEntry>` | 3 production servers | Override for air-gapped or private deployments. |
| `min_quorum` | `uint32_t` | `3` | BFT bound: total ≥ 3×faulty + 1. |
| `max_total_drift` | `int64_t` | `3600` | Maximum cumulative drift in seconds. |
| `max_drift_step` | `int64_t` | `60` | Per-sync correction clamp in seconds. |
| `max_cluster_skew` | `int64_t` | `10` | Intra-cluster spread in seconds. |
| `sync_interval_s` | `int` | `60` | Background sync period in seconds. |
| `fail_before_sync` | `bool` | `false` | Return invalid anchors until first sync completes. |

---

## TimeAnchor Field Reference

| Field | Type | Description |
|---|---|---|
| `logical_time` | `uint64_t` | BFT-agreed Unix seconds. Monotonically increasing within a process. Use as ordering key. |
| `drift_us` | `int64_t` | Applied drift in microseconds at capture time. Useful for diagnostics. |
| `uncertainty_s` | `uint64_t` | Seconds since last confirmed sync. Rises between syncs; resets to 0 on each successful quorum round. |
| `proof` | `string` | Self-contained proof: `canonical_payload\|hmac_signature`. Store this field verbatim. |
| `authority` | `string` | Sorted comma-joined list of NTP sources that formed the quorum at last sync. |
| `event_id` | `string` | Caller-supplied event identifier (empty for `now()` anchors). |
| `is_valid` | `bool` | False until at least one successful BFT sync has completed. |

---

## Key Rotation

When rotating the HMAC key:

1. Generate a new key: `uml001::generate_random_bytes_hex(32)`
2. Register it: `uml001::register_hmac_authority(hostname, new_key_id, new_key_hex)` for each NTP server.
3. Construct a new `QuorumTimeAdapter` with the new `hmac_key` and incremented `key_id`.
4. Persist both the old and new key_id → key mappings in your key store. Anchors issued under the old key_id must be verified with the old key.
5. The consuming application's key-rotation manager is responsible for presenting the correct key during verification. `QuorumTimeAdapter::verify()` uses the key present at construction time; it does not multi-key-resolve.

---

## Diagnostics

```cpp
// Health check integration:
bool is_healthy = adapter.is_running()
               && adapter.sync_count() > 0
               && adapter.error_count() < threshold;

// Drift monitoring:
int64_t drift_us = adapter.current_drift_us();
// Expected range in production: ±1,000,000 µs (±1 second).
// Values approaching max_total_drift * 1,000,000 indicate a problem.

// Quorum success rate:
double success_rate = static_cast<double>(adapter.sync_count())
                    / (adapter.sync_count() + adapter.error_count());
```

---

## Security Properties

**What the proof guarantees:**
- The `logical_time` was derived from a Byzantine-fault-tolerant consensus
  across `min_quorum` independent NTP authorities at or before the anchor
  was issued.
- The `proof` field is HMAC-SHA256 signed under `hmac_key`, binding the
  timestamp, observation hash, and (for `anchor_event()`) the specific
  event payload hash. Tampering with any field invalidates the signature.
- Replay attacks are prevented by the `NtpObservationFetcher`'s monotonic
  per-authority sequence counters, enforced in
  `BFTQuorumTrustedClock::verify_observation()`.

**What the proof does not guarantee:**
- Absolute wall-clock accuracy beyond the configured drift bounds.
- Protection against a compromised NTP server pool if fewer than
  `min_quorum` honest servers remain.
- Forward secrecy: if the `hmac_key` is compromised, historical anchors
  can be forged. Use a KMS with key rotation for high-assurance deployments.

---

## NTP Server Configuration for Air-Gapped Deployments

If the deployment environment cannot reach public NTP servers, supply
an internal pool via `cfg.ntp_servers`:

```cpp
cfg.ntp_servers = {
    { "ntp-1.internal.example.com", 500, 1000 },
    { "ntp-2.internal.example.com", 500, 1000 },
    { "ntp-3.internal.example.com", 500, 1000 }
};
```

Register the HMAC key for each internal server — `QuorumTimeAdapter`'s
constructor calls `register_hmac_authority()` automatically for every
entry in `cfg.ntp_servers`. No manual registration step is required.

---

## Thread Safety Summary

| Operation | Thread-safe | Notes |
|---|---|---|
| `start()` | Yes | Idempotent. |
| `stop()` | Yes | Idempotent. Blocks until thread joins. |
| `now()` | Yes | Acquires BFT clock mutex only. Non-blocking. |
| `anchor_event()` | Yes | Acquires BFT clock mutex only. Non-blocking. |
| `verify()` | Yes | Read-only. HMAC computation only. |
| `sync_count()` | Yes | Atomic load. |
| `error_count()` | Yes | Atomic load. |
| `current_drift_us()` | Yes | Acquires BFT clock mutex. |

The adapter does not hold any lock across `now()` or `anchor_event()` calls
from the caller's perspective. The BFT clock's internal mutex is acquired
for the duration of the read (~microseconds) and released before the call
returns.

---

## Optional REST Server Smoke Check

The repository includes an optional Pistache-based REST server target for
local validation:

```bash
cmake -S . -B build -DBUILD_REST_SERVER=ON
cmake --build build -j
```

If `libpistache` is available, this produces `build/uml001_rest_server`.

Run the smoke script:

```bash
./tools/smoke_rest_server.sh
```

The script validates:
- `GET /time/now` returns `200`
- `POST /time/shared-state` returns `200` (accepted) or `403` (rejected by convergence/signature/version checks)

---

## gRPC Metadata De-scope (Current Contract)

`proto/clock_service.proto` includes several fields that are intentionally
de-scoped in the current runtime API surface. They are present for
compatibility and future extension, but **must not** be treated as
cryptographic or version authority today.

### De-scoped fields (current runtime values)

- `TimeResponse.monotonic_version` -> `0`
- `TimeResponse.signature` -> `""`
- `TimeResponse.key_id` -> `""`
- `TimeResponse.alignment_context_id` -> `""`
- `AlignTimeResponse.signature_proof` -> empty bytes
- `StatusResponse.current_version` -> `0`

### Authoritative alternatives

Use these instead of the de-scoped gRPC metadata fields:

- **Proof / authenticity**: `TimeAnchor.proof` (binary `SignedState` envelope)
- **Anchor semantics**: `SignedState::anchor_proof` (`AnchorProof` in `signed_state.proto`)
- **Shared-state versioning**: internal shared-state event payload fields
  (`monotonic_version`, etc.) routed through the orchestrated pipeline

### Integration rule

If your consumer requires signed timestamp attestations or versioned replay
guards, integrate via `QuorumTimeAdapter` (`now()`, `anchor_event()`,
`verify()`) and/or shared-state pipeline events. Do not gate security decisions
on the de-scoped gRPC metadata fields above.