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
#include "uml001/stages/recovery_stage.h"

#include "uml001/crypto_utils.h"
#include "uml001/pipeline_event_ids.h"

namespace uml001 {

namespace {
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

RecoveryStage::RecoveryStage(RuntimeModeMachine* machine)
    : machine_(machine) {}

void RecoveryStage::execute(EventContext& ctx)
{
    if (ctx.aborted || !machine_) {
        return;
    }

    const std::string& id = ctx.event.event_id();
    if (id == pipeline::CONTROL_RECOVERY_BEGIN) {
        if (!require_control_signature(ctx)) {
            return;
        }
        if (!machine_->transition(RuntimeMode::RECOVERY, "recovery_begin")) {
            ctx.aborted = true;
            ctx.audit_reason = "recovery_begin_rejected";
        }
        return;
    }
    if (id == pipeline::CONTROL_RECOVERY_EPOCH_VERIFIED) {
        if (!require_control_signature(ctx)) {
            return;
        }
        if (!machine_->set_recovery_epoch_verified()) {
            ctx.aborted = true;
            ctx.audit_reason = "recovery_epoch_verify_rejected";
        }
        return;
    }
    if (id == pipeline::CONTROL_RECOVERY_REJOIN) {
        if (!require_control_signature(ctx)) {
            return;
        }
        if (!machine_->recovery_epoch_verified()) {
            ctx.aborted = true;
            ctx.audit_reason = "recovery_rejoin_without_epoch";
            return;
        }
        if (!machine_->transition(RuntimeMode::QUORUM_ACTIVE, "recovery_rejoin")) {
            ctx.aborted = true;
            ctx.audit_reason = "recovery_rejoin_rejected";
        }
        return;
    }

    if (machine_->mode() == RuntimeMode::RECOVERY &&
        id != pipeline::GRPC_GET_TIME &&
        id != pipeline::GRPC_GET_STATUS &&
        id != pipeline::GRPC_ALIGN_TIME &&
        id != pipeline::REST_TIME_NOW) {
        ctx.aborted = true;
        ctx.audit_reason = "recovery_write_blocked";
    }
}

} // namespace uml001
