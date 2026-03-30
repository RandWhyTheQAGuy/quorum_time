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
#include "uml001/stages/hitl_gate_stage.h"

#include "uml001/crypto_utils.h"
#include "uml001/pipeline_event_ids.h"

namespace uml001 {

namespace {
bool is_hitl_control_event(const std::string& id)
{
    return id == pipeline::CONTROL_HITL_APPROVE || id == pipeline::CONTROL_HITL_REJECT;
}

std::string canonical_passport_payload(const SignedState& event)
{
    const std::string payload_hash = sha256_hex(event.payload());
    return event.event_id() + "|" +
           std::to_string(event.logical_time_ns()) + "|" +
           event.key_id() + "|" +
           payload_hash;
}

std::string passport_authority_id(const SignedState& event)
{
    if (!event.gossip().origin_node_id().empty()) {
        return event.gossip().origin_node_id();
    }
    return "local";
}

bool require_control_signature(EventContext& ctx)
{
    if (ctx.event.signature().empty()) {
        ctx.aborted = true;
        ctx.audit_reason = "passport_signature_missing";
        return false;
    }
    const std::string canonical = canonical_passport_payload(ctx.event);
    const std::string authority = passport_authority_id(ctx.event);
    if (!crypto_verify(canonical, ctx.event.signature(), authority, ctx.event.key_id())) {
        ctx.aborted = true;
        ctx.audit_reason = "passport_signature_invalid";
        return false;
    }
    return true;
}
} // namespace

HitlGateStage::HitlGateStage(RuntimeModeMachine* machine)
    : machine_(machine) {}

void HitlGateStage::execute(EventContext& ctx)
{
    if (ctx.aborted || !machine_) {
        return;
    }

    const std::string& id = ctx.event.event_id();
    if (is_hitl_control_event(id)) {
        if (!require_control_signature(ctx)) {
            return;
        }
        if (id == pipeline::CONTROL_HITL_REJECT) {
            machine_->transition(RuntimeMode::HITL_HOLD, "hitl_reject");
        } else {
            machine_->transition(RuntimeMode::RECOVERY, "hitl_approve");
        }
        return;
    }

    const RuntimeMode mode = machine_->mode();
    if (mode == RuntimeMode::HITL_HOLD) {
        ctx.aborted = true;
        ctx.audit_reason = "hitl_hold_blocked";
        return;
    }

    if (ctx.event.payload().find("requires_hitl=1") != std::string::npos) {
        ctx.aborted = true;
        ctx.audit_reason = "hitl_required_not_approved";
        // Do not mutate runtime mode from free-form payload markers.
        // Mode transitions must occur only via signed control events.
    }
}

} // namespace uml001
