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
#include "uml001/event_orchestrator.h"
#include "uml001/stages/circuit_breaker_stage.h"
#include "uml001/stages/hitl_gate_stage.h"
#include "uml001/stages/mode_control_stage.h"
#include "uml001/stages/quarantine_stage.h"
#include "uml001/stages/recovery_stage.h"

#include <chrono>
#include <exception>

namespace uml001 {

namespace {
bool runs_post_abort_only(const char* stage_name)
{
    return std::string(stage_name) == "CircuitBreakerStage" ||
           std::string(stage_name) == "QuarantineStage";
}
}

EventOrchestrator::EventOrchestrator(IStrongClock* clock, ColdVault* audit_vault)
    : clock_(clock), audit_vault_(audit_vault), mode_machine_(std::make_unique<RuntimeModeMachine>(audit_vault))
{
    register_stage(std::make_unique<ModeControlStage>(mode_machine_.get()));
    register_stage(std::make_unique<HitlGateStage>(mode_machine_.get()));
    register_stage(std::make_unique<RecoveryStage>(mode_machine_.get()));
    register_stage(std::make_unique<CircuitBreakerStage>(mode_machine_.get()));
    register_stage(std::make_unique<QuarantineStage>(audit_vault_));
}

// ============================================================
// Register Stage
// ============================================================

void EventOrchestrator::register_stage(std::unique_ptr<IEventPipelineStage> stage) {
    std::lock_guard<std::mutex> g(lock_);
    stages_.push_back(std::move(stage));
}

// ============================================================
// Ingest Entry Point
// ============================================================

void EventOrchestrator::ingest(const SignedState& event) {
    (void)ingest_with_context(event);
}

EventContext EventOrchestrator::ingest_with_context(const SignedState& event) {
    EventContext ctx;
    ctx.event = event;

    if (clock_) {
        ctx.received_at_ns = clock_->now_unix() * 1000000000ULL;
    } else {
        ctx.received_at_ns =
            std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }

    ctx.hop_count = event.gossip().hops();
    ctx.is_converged = false;

    execute_pipeline(ctx);

    std::lock_guard<std::mutex> g(lock_);
    last_ctx_ = ctx;
    return ctx;
}

// ============================================================
// Pipeline Execution (STRICT ORDER GUARANTEE)
// ============================================================

void EventOrchestrator::execute_pipeline(EventContext& ctx) {
    bool aborted_during_pipeline = false;
    for (auto& stage : stages_) {
        if (ctx.aborted && !runs_post_abort_only(stage->name())) {
            aborted_during_pipeline = true;
            break;
        }
        const std::string before_reason = ctx.audit_reason;
        try {
            stage->execute(ctx);
        } catch (const std::exception& e) {
            ctx.aborted = true;
            ctx.audit_reason = "pipeline_exception";
            if (audit_vault_) {
                audit_vault_->log_security_event(
                    "pipeline.exception",
                    "stage=" + std::string(stage->name()) + " what=" + e.what());
            }
        } catch (...) {
            ctx.aborted = true;
            ctx.audit_reason = "pipeline_exception";
            if (audit_vault_) {
                audit_vault_->log_security_event(
                    "pipeline.exception",
                    "stage=" + std::string(stage->name()) + " what=unknown");
            }
        }
        if (audit_vault_ && !ctx.audit_reason.empty() && ctx.audit_reason != before_reason) {
            audit_vault_->log_security_event(
                "pipeline.event",
                "stage=" + std::string(stage->name()) +
                " reason=" + ctx.audit_reason +
                " event_id=" + ctx.event.event_id());
            ctx.audit_stage = stage->name();
        }
        if (ctx.aborted) {
            aborted_during_pipeline = true;
            break;
        }
    }

    if (!aborted_during_pipeline) {
        return;
    }

    // Explicit post-abort policy: run only safety stages.
    for (auto& stage : stages_) {
        if (!runs_post_abort_only(stage->name())) {
            continue;
        }
        const std::string before_reason = ctx.audit_reason;
        try {
            stage->execute(ctx);
        } catch (const std::exception& e) {
            ctx.aborted = true;
            if (ctx.audit_reason.empty() || ctx.audit_reason == "quarantine_logged") {
                ctx.audit_reason = "pipeline_exception";
            }
            if (audit_vault_) {
                audit_vault_->log_security_event(
                    "pipeline.exception",
                    "stage=" + std::string(stage->name()) + " what=" + e.what());
            }
        } catch (...) {
            ctx.aborted = true;
            if (ctx.audit_reason.empty() || ctx.audit_reason == "quarantine_logged") {
                ctx.audit_reason = "pipeline_exception";
            }
            if (audit_vault_) {
                audit_vault_->log_security_event(
                    "pipeline.exception",
                    "stage=" + std::string(stage->name()) + " what=unknown");
            }
        }
        if (audit_vault_ && !ctx.audit_reason.empty() && ctx.audit_reason != before_reason) {
            audit_vault_->log_security_event(
                "pipeline.event",
                "stage=" + std::string(stage->name()) +
                " reason=" + ctx.audit_reason +
                " event_id=" + ctx.event.event_id());
            ctx.audit_stage = stage->name();
        }
    }
}

// ============================================================
// Snapshot
// ============================================================

EventContext EventOrchestrator::last_context_snapshot() const {
    std::lock_guard<std::mutex> g(lock_);
    return last_ctx_;
}

} // namespace uml001