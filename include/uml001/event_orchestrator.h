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

#include <vector>
#include <memory>
#include <mutex>

#include "event_context.h"
#include "event_pipeline_stage.h"
#include "uml001/runtime_mode_machine.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

namespace uml001 {

// ============================================================
// EventOrchestrator (Maestro)
// SINGLE SOURCE OF EVENT TRUTH
// ============================================================

class EventOrchestrator {
public:
    explicit EventOrchestrator(IStrongClock* clock, ColdVault* audit_vault);

    // Register deterministic pipeline stages
    void register_stage(std::unique_ptr<IEventPipelineStage> stage);

    // Entry point for ALL system events
    void ingest(const SignedState& event);
    EventContext ingest_with_context(const SignedState& event);

    // Observability hook (vault + debugging)
    EventContext last_context_snapshot() const;

private:
    void execute_pipeline(EventContext& ctx);

private:
    std::vector<std::unique_ptr<IEventPipelineStage>> stages_;
    IStrongClock* clock_;
    ColdVault* audit_vault_;
    std::unique_ptr<RuntimeModeMachine> mode_machine_;

    mutable std::mutex lock_;
    EventContext last_ctx_;
};

} // namespace uml001