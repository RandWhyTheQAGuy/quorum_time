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
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <memory>

#include "crypto_mode.h"

namespace uml001 {

// Forward declarations
class ColdVault;
class NtpObservationFetcher;

class KeyRotationManager {
public:
    struct Config {
        uint64_t rotation_interval_seconds = 3600;
        uint64_t overlap_window_seconds    = 180;
        CryptoConfig crypto;
    };

    // Declare constructor only
    KeyRotationManager(
        std::shared_ptr<ColdVault> vault,
        const std::unordered_set<std::string>& authorities,
        Config config
    );

    void maybe_rotate(uint64_t strong_time);
    void configure_fetcher(NtpObservationFetcher& fetcher);

    bool verify_with_overlap(
        const std::string& authority,
        const std::string& payload,
        const std::string& signature,
        uint64_t strong_time
    );

    uint64_t key_version() const;
    CryptoMode mode() const;

private:
    void rotate_hmac(uint64_t strong_time);
    void rotate_ed25519(uint64_t strong_time);
    void rotate_tpm(uint64_t strong_time);

    std::shared_ptr<ColdVault> vault_;
    std::unordered_set<std::string> authorities_;
    Config config_;

    // State management
    std::string current_hmac_;
    std::string previous_hmac_;
    std::string current_private_key_;
    std::string current_public_key_;
    std::string previous_public_key_;

    uint64_t previous_key_expiry_ = 0;
    uint64_t key_version_         = 0;
    uint64_t last_rotation_unix_  = 0;

    mutable std::mutex mutex_;
};

} // namespace uml001