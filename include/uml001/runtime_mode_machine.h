/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
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
 *   - BFT Quorum Time: multi-authority, tamper-evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross-domain alignment (AlignTime).
 *
 *   - Transparency Logging: append-only, hash-chained audit records
 *                           for time events, alignment proofs, and
 *                           key-rotation operations.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security-critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open-source project with a focus on
 * clarity, auditability, and long-term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community-driven evolution of verifiable time and
 * distributed trust standards.
 */
#pragma once

#include <cstdint>
#include <mutex>
#include <string>

namespace uml001 {

class ColdVault;

enum class RuntimeMode : std::uint8_t {
    COLD_START = 0,
    QUORUM_ACTIVE = 1,
    DEGRADED = 2,
    ISOLATED = 3,
    RECOVERY = 4,
    HITL_HOLD = 5
};

class RuntimeModeMachine {
public:
    explicit RuntimeModeMachine(ColdVault* vault, std::uint32_t breaker_threshold = 8);

    RuntimeMode mode() const;
    bool transition(RuntimeMode next, const std::string& reason);

    void note_rejection();
    void note_success();
    bool should_trip_breaker() const;
    std::uint32_t rejection_streak() const;

    bool set_recovery_epoch_verified();
    bool recovery_epoch_verified() const;

    static const char* to_string(RuntimeMode mode);
    static bool from_string(const std::string& raw, RuntimeMode& out_mode);

private:
    ColdVault* vault_;
    std::uint32_t breaker_threshold_;

    mutable std::mutex mu_;
    RuntimeMode mode_ = RuntimeMode::COLD_START;
    std::uint32_t rejection_streak_ = 0;
    bool recovery_epoch_verified_ = false;
};

} // namespace uml001
