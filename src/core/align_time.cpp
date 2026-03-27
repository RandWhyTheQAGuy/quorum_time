/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine‑resilient trusted‑time
 * system designed for modern distributed environments. It provides a
 * cryptographically anchored notion of time that can be aligned,
 * audited, and shared across domains without requiring centralized
 * trust.
 *
 * This project also includes the Aegis Semantic Passport components,
 * which complement Quorum Time by offering structured, verifiable
 * identity and capability attestations for agents and services.
 *
 * Core capabilities:
 *   - BFT Quorum Time: multi‑authority, tamper‑evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross‑domain alignment (AlignTime).
 *
 *   - Transparency Logging: append‑only, hash‑chained audit records
 *                           for time events, alignment proofs, and
 *                           key‑rotation operations.
 *
 *   - Semantic Passports: optional identity and capability metadata
 *                         for systems that require verifiable agent
 *                         provenance and authorization context.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security‑critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open‑source project with a focus on
 * clarity, auditability, and long‑term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community‑driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/align_time.h"
#include <algorithm>
#include <cstring>

namespace uml001 {

std::vector<uint8_t> AlignTimeManager::pack_for_signing(const AlignmentPoint& point) const {
    std::vector<uint8_t> buffer;
    
    // PeerID and SessionID strings
    buffer.insert(buffer.end(), point.peer_id.begin(), point.peer_id.end());
    buffer.insert(buffer.end(), point.session_id.begin(), point.session_id.end());

    // Fixed-width timestamp (uint64_t)
    uint64_t ts = point.timestamp;
    const uint8_t* ts_ptr = reinterpret_cast<const uint8_t*>(&ts);
    buffer.insert(buffer.end(), ts_ptr, ts_ptr + sizeof(ts));

    // Anchors
    buffer.insert(buffer.end(), point.local_anchor.begin(), point.local_anchor.end());
    buffer.insert(buffer.end(), point.remote_anchor.begin(), point.remote_anchor.end());

    return buffer;
}

void AlignTimeManager::sign_local(AlignmentPoint& point) {
    auto payload = pack_for_signing(point);
    point.signature = signer_.sign(payload);
}

bool AlignTimeManager::verify_remote(const AlignmentPoint& point, 
                                     const std::vector<uint8_t>& peer_public_key) {
    if (point.signature.empty()) return false;
    
    auto payload = pack_for_signing(point);
    
    // We utilize the verify method from crypto_interfaces.h
    // This maintains the ZK/ZN principle: we don't need the peer's raw logs,
    // only the signed anchor that proves their state existed at time T.
    return signer_.verify(payload, point.signature);
}

} // namespace uml001