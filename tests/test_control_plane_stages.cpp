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
#include <cassert>
#include <filesystem>
#include <memory>
#include <unordered_set>

#include "uml001/bft_quorum_clock.h"
#include "uml001/event_context.h"
#include "uml001/pipeline_event_ids.h"
#include "uml001/runtime_mode_machine.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/stages/circuit_breaker_stage.h"
#include "uml001/stages/hitl_gate_stage.h"
#include "uml001/stages/mode_control_stage.h"
#include "uml001/stages/passport_validation_stage.h"
#include "uml001/stages/quarantine_stage.h"
#include "uml001/stages/recovery_stage.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

int main()
{
    namespace fs = std::filesystem;
    using namespace uml001;

    const fs::path dir = fs::temp_directory_path() / "quorum_time_test_control_plane_stages";
    fs::create_directories(dir);

    OsStrongClock strong_clock;
    SimpleHashProvider hash_provider;
    auto backend = std::make_shared<SimpleFileVaultBackend>(dir / "vault.log");
    ColdVault::Config vault_cfg;
    vault_cfg.base_directory = dir;
    auto vault = std::make_shared<ColdVault>(vault_cfg, backend, strong_clock, hash_provider);

    RuntimeModeMachine machine(vault.get(), 1);

    // ModeControlStage: control events must be signature-gated before payload parsing.
    {
        ModeControlStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::CONTROL_SET_MODE);
        ctx.event.set_payload("BAD_MODE");
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
    }

    // ModeControlStage: isolated mode blocks non-read events.
    {
        assert(machine.transition(RuntimeMode::ISOLATED, "test"));
        ModeControlStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::WORKER_NTP_SYNC);
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "mode_isolated_blocked");
    }

    // HitlGateStage: payload requiring HITL should be blocked and mode changed.
    {
        assert(machine.transition(RuntimeMode::RECOVERY, "test"));
        assert(machine.transition(RuntimeMode::QUORUM_ACTIVE, "test"));
        HitlGateStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::WORKER_NTP_SYNC);
        ctx.event.set_payload("requires_hitl=1");
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "hitl_required_not_approved");
        assert(machine.mode() == RuntimeMode::QUORUM_ACTIVE);
    }

    // RecoveryStage: control events are signature-gated before recovery checks.
    {
        assert(machine.transition(RuntimeMode::RECOVERY, "test"));
        RecoveryStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::CONTROL_RECOVERY_REJOIN);
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
    }

    // CircuitBreakerStage: rejection streak trips breaker and marks audit reason.
    {
        CircuitBreakerStage stage(&machine);
        EventContext ctx;
        ctx.aborted = true;
        ctx.audit_reason = "passport_signature_missing";
        stage.execute(ctx);
        assert(machine.mode() == RuntimeMode::DEGRADED);
        assert(ctx.audit_reason == "circuit_breaker_tripped");
    }

    // QuarantineStage: aborted event gets quarantine marker side effect.
    {
        QuarantineStage stage(vault.get());
        EventContext ctx;
        ctx.aborted = true;
        ctx.audit_reason = "mode_isolated_blocked";
        ctx.event.set_event_id(pipeline::WORKER_NTP_SYNC);
        stage.execute(ctx);
        assert(ctx.audit_reason == "quarantine_logged");
    }

    // PassportValidationStage: missing signature on non-allowlisted event is rejected.
    {
        gossip::GossipDedup dedup;
        PassportValidationStage stage(&dedup);
        EventContext ctx;
        ctx.event.set_event_id("uml001.unknown.mutating_event");
        ctx.event.set_payload("x");
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
    }

    // PassportValidationStage: allowlisted synthetic event may be unsigned.
    {
        gossip::GossipDedup dedup;
        PassportValidationStage stage(&dedup);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::REST_TIME_NOW);
        stage.execute(ctx);
        assert(!ctx.aborted);
    }

    // PassportValidationStage: control-plane event must not be unsigned.
    {
        gossip::GossipDedup dedup;
        PassportValidationStage stage(&dedup);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::CONTROL_SET_MODE);
        ctx.event.set_payload("RECOVERY");
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
    }

    // HitlGateStage: unsigned control event must not mutate runtime mode.
    {
        assert(machine.transition(RuntimeMode::QUORUM_ACTIVE, "test"));
        HitlGateStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::CONTROL_HITL_REJECT);
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
        assert(machine.mode() == RuntimeMode::QUORUM_ACTIVE);
    }

    // RecoveryStage: unsigned control event must not mutate runtime mode.
    {
        assert(machine.transition(RuntimeMode::RECOVERY, "test"));
        RecoveryStage stage(&machine);
        EventContext ctx;
        ctx.event.set_event_id(pipeline::CONTROL_RECOVERY_BEGIN);
        stage.execute(ctx);
        assert(ctx.aborted);
        assert(ctx.audit_reason == "passport_signature_missing");
        assert(machine.mode() == RuntimeMode::RECOVERY);
    }

    return 0;
}
