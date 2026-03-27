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
/**
 * @file hardened_clock.h
 * @brief Logic for Quorum-First Initialization and state transitions.
 */

#include <string>
#include <atomic>
#include <cstdint>

namespace uml001 {

/**
 * @enum TrustLevel
 * @brief Defines the operational readiness of the Aegis Clock.
 */
enum class TrustLevel {
    COLD_BOOT,      ///< No data yet; clock is strictly local and untrusted.
    WARMING,        ///< Receiving data but below BFT quorum (N < 3F+1).
    STABLE_QUORUM,  ///< Full BFT consensus reached; safe for production use.
    DEGRADED        ///< Previously stable, but quorum has been lost.
};

class ClockGovernor {
public:
    explicit ClockGovernor(uint32_t min_quorum) : min_quorum_(min_quorum) {}

    /**
     * @brief Updates state based on observation count and returns true if trusted.
     */
    bool update_and_check(size_t observation_count) {
        if (observation_count >= min_quorum_) {
            state_ = TrustLevel::STABLE_QUORUM;
            return true;
        }
        
        if (state_ == TrustLevel::STABLE_QUORUM && observation_count < min_quorum_) {
            state_ = TrustLevel::DEGRADED;
        } else if (observation_count > 0 && state_ == TrustLevel::COLD_BOOT) {
            state_ = TrustLevel::WARMING;
        }
        return (state_ == TrustLevel::STABLE_QUORUM);
    }

    TrustLevel get_state() const { return state_; }
    uint32_t get_min_quorum() const { return min_quorum_; }

private:
    TrustLevel state_ = TrustLevel::COLD_BOOT;
    uint32_t min_quorum_;
};

} // namespace uml001