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
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "uml001/crypto_interfaces.h"

namespace uml001 {

/**
 * @brief Deterministic cryptographic alignment anchor.
 *
 * SECURITY MODEL:
 * - Timestamp MUST originate from BFTQuorumTrustedClock
 * - Anchors MUST be Merkle-root derived hashes
 * - Signature binds: peer_id + session_id + timestamp + anchors
 */
struct AlignmentPoint {
    std::string peer_id;
    std::string session_id;
    std::string key_id;

    uint64_t timestamp = 0; // ALWAYS from BFTQuorumTrustedClock

    std::vector<uint8_t> local_anchor;   // local Merkle root
    std::vector<uint8_t> remote_anchor;  // peer Merkle root

    std::vector<uint8_t> signature;      // signature over packed payload
};

class AlignTimeManager {
public:
    AlignTimeManager(ISignProvider& signer, IHashProvider& hasher)
        : signer_(signer), hasher_(hasher) {}

    /**
     * Canonical serialization for signing.
     * MUST remain stable across versions (security-critical).
     */
    std::vector<uint8_t> pack_for_signing(const AlignmentPoint& point) const;

    /**
     * Signs alignment point using local private key.
     */
    void sign_local(AlignmentPoint& point);

    /**
     * Verifies remote alignment proof.
     * NOTE: public key resolution must be externalized via key_id.
     */
    bool verify_remote(const AlignmentPoint& point,
                       const std::vector<uint8_t>& peer_public_key);

private:
    ISignProvider& signer_;
    IHashProvider& hasher_;
};

} // namespace uml001