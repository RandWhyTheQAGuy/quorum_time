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
#include <cstdint>
#include <chrono>
#include <string>

namespace uml001 {

/**
 * @brief Abstract interface for trusted time sources.
 * Conforms to NIST SP 800-53 (AU-12) for authoritative time-stamping.
 */
class IStrongClock {
public:
    virtual ~IStrongClock() = default;
    
    /**
     * @brief Returns current Unix timestamp in seconds.
     */
    virtual std::uint64_t now_unix() const = 0;

    /**
     * @brief Returns the current estimated drift in microseconds.
     */
    virtual std::int64_t get_current_drift() const = 0;
};

// NOTE: IHashProvider has been moved to uml001/hash_provider.h 
// to prevent redefinition errors during compilation.

/**
 * @brief OS-backed strong clock — direct view of the system wall clock.
 */
class OsStrongClock : public IStrongClock {
public:
    std::uint64_t now_unix() const override {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
    }

    std::int64_t get_current_drift() const override {
        // Raw OS clock carries no drift correction.
        return 0;
    }
};

} // namespace uml001