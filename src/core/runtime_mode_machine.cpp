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
#include "uml001/runtime_mode_machine.h"

#include "uml001/vault.h"

namespace uml001 {

RuntimeModeMachine::RuntimeModeMachine(ColdVault* vault, std::uint32_t breaker_threshold)
    : vault_(vault), breaker_threshold_(breaker_threshold == 0 ? 1 : breaker_threshold) {}

RuntimeMode RuntimeModeMachine::mode() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return mode_;
}

bool RuntimeModeMachine::transition(RuntimeMode next, const std::string& reason)
{
    std::lock_guard<std::mutex> lock(mu_);
    const RuntimeMode prev = mode_;
    if (prev == next) {
        return true;
    }

    bool allowed = false;
    switch (prev) {
    case RuntimeMode::COLD_START:
        allowed = (next == RuntimeMode::RECOVERY || next == RuntimeMode::QUORUM_ACTIVE ||
                   next == RuntimeMode::DEGRADED || next == RuntimeMode::ISOLATED ||
                   next == RuntimeMode::HITL_HOLD);
        break;
    case RuntimeMode::RECOVERY:
        allowed = (next == RuntimeMode::QUORUM_ACTIVE || next == RuntimeMode::DEGRADED ||
                   next == RuntimeMode::ISOLATED || next == RuntimeMode::HITL_HOLD);
        break;
    case RuntimeMode::QUORUM_ACTIVE:
        allowed = (next == RuntimeMode::DEGRADED || next == RuntimeMode::ISOLATED ||
                   next == RuntimeMode::HITL_HOLD || next == RuntimeMode::RECOVERY);
        break;
    case RuntimeMode::DEGRADED:
        allowed = (next == RuntimeMode::QUORUM_ACTIVE || next == RuntimeMode::ISOLATED ||
                   next == RuntimeMode::HITL_HOLD || next == RuntimeMode::RECOVERY);
        break;
    case RuntimeMode::ISOLATED:
        allowed = (next == RuntimeMode::RECOVERY || next == RuntimeMode::HITL_HOLD);
        break;
    case RuntimeMode::HITL_HOLD:
        allowed = (next == RuntimeMode::RECOVERY || next == RuntimeMode::DEGRADED ||
                   next == RuntimeMode::ISOLATED || next == RuntimeMode::QUORUM_ACTIVE);
        break;
    }

    if (!allowed) {
        if (vault_) {
            vault_->log_security_event(
                "runtime.mode.reject",
                std::string("from=") + to_string(prev) + " to=" + to_string(next) +
                    " reason=" + reason);
        }
        return false;
    }

    mode_ = next;
    if (next != RuntimeMode::RECOVERY) {
        recovery_epoch_verified_ = false;
    }
    if (vault_) {
        vault_->log_security_event(
            "runtime.mode.transition",
            std::string("from=") + to_string(prev) + " to=" + to_string(next) +
                " reason=" + reason);
    }
    return true;
}

void RuntimeModeMachine::note_rejection()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (rejection_streak_ < UINT32_MAX) {
        ++rejection_streak_;
    }
}

void RuntimeModeMachine::note_success()
{
    std::lock_guard<std::mutex> lock(mu_);
    rejection_streak_ = 0;
}

bool RuntimeModeMachine::should_trip_breaker() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return rejection_streak_ >= breaker_threshold_;
}

std::uint32_t RuntimeModeMachine::rejection_streak() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return rejection_streak_;
}

bool RuntimeModeMachine::set_recovery_epoch_verified()
{
    std::lock_guard<std::mutex> lock(mu_);
    if (mode_ != RuntimeMode::RECOVERY) {
        return false;
    }
    recovery_epoch_verified_ = true;
    return true;
}

bool RuntimeModeMachine::recovery_epoch_verified() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return recovery_epoch_verified_;
}

const char* RuntimeModeMachine::to_string(RuntimeMode mode)
{
    switch (mode) {
    case RuntimeMode::COLD_START: return "COLD_START";
    case RuntimeMode::QUORUM_ACTIVE: return "QUORUM_ACTIVE";
    case RuntimeMode::DEGRADED: return "DEGRADED";
    case RuntimeMode::ISOLATED: return "ISOLATED";
    case RuntimeMode::RECOVERY: return "RECOVERY";
    case RuntimeMode::HITL_HOLD: return "HITL_HOLD";
    }
    return "UNKNOWN";
}

bool RuntimeModeMachine::from_string(const std::string& raw, RuntimeMode& out_mode)
{
    if (raw == "COLD_START") { out_mode = RuntimeMode::COLD_START; return true; }
    if (raw == "QUORUM_ACTIVE") { out_mode = RuntimeMode::QUORUM_ACTIVE; return true; }
    if (raw == "DEGRADED") { out_mode = RuntimeMode::DEGRADED; return true; }
    if (raw == "ISOLATED") { out_mode = RuntimeMode::ISOLATED; return true; }
    if (raw == "RECOVERY") { out_mode = RuntimeMode::RECOVERY; return true; }
    if (raw == "HITL_HOLD") { out_mode = RuntimeMode::HITL_HOLD; return true; }
    return false;
}

} // namespace uml001
