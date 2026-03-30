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
#include "uml001/stages/passport_validation_stage.h"
#include "uml001/crypto_utils.h"
#include "uml001/pipeline_event_ids.h"

namespace uml001 {

PassportValidationStage::PassportValidationStage(gossip::GossipDedup* dedup)
    : dedup_(dedup) {}

namespace {

std::string canonical_passport_payload(const SignedState& event)
{
    // Stable canonical form across nodes; excludes mutable transit metadata.
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

bool is_unsigned_synthetic_event_allowed(const std::string& event_id)
{
    return event_id == pipeline::GRPC_GET_TIME ||
           event_id == pipeline::GRPC_GET_STATUS ||
           event_id == pipeline::GRPC_ALIGN_TIME ||
           event_id == pipeline::REST_TIME_NOW ||
           event_id == pipeline::REST_TIME_SYNC ||
           event_id == pipeline::REST_TIME_SHARED_STATE ||
           event_id == pipeline::REST_AUTH_FAILED ||
           event_id == pipeline::WORKER_NTP_SYNC ||
           event_id == pipeline::INTERNAL_SHARED_STATE_APPLY;
}

} // namespace

void PassportValidationStage::execute(EventContext& ctx)
{
    if (ctx.aborted) {
        return;
    }

    // Deterministic fail-closed passport validation before side effects.
    const std::string& signature = ctx.event.signature();
    const std::string& event_id = ctx.event.event_id();
    const bool is_gossip_ingress = !ctx.event.gossip().origin_node_id().empty();

    if (signature.empty()) {
        if (is_gossip_ingress || !is_unsigned_synthetic_event_allowed(event_id)) {
            ctx.aborted = true;
            ctx.audit_reason = "passport_signature_missing";
            return;
        }
    } else {
        const std::string canonical = canonical_passport_payload(ctx.event);
        const std::string authority = passport_authority_id(ctx.event);
        bool ok = false;
        try {
            ok = crypto_verify(
                canonical,
                signature,
                authority,
                ctx.event.key_id());
        } catch (...) {
            ok = false;
        }
        if (!ok) {
            ctx.aborted = true;
            ctx.audit_reason = "passport_signature_invalid";
            return;
        }
    }

    // Gossip ingress dedup by (event_id, origin_node_id). Non-gossip events have empty origin.
    const std::string origin = ctx.event.gossip().origin_node_id();
    if (!origin.empty()) {
        if (!dedup_) {
            ctx.aborted = true;
            ctx.audit_reason = "gossip_dedup_missing";
            return;
        }
        if (dedup_->is_duplicate(ctx.event)) {
            ctx.aborted = true;
            ctx.audit_reason = "gossip_duplicate_rejected";
            return;
        }
        dedup_->mark_seen(ctx.event);
    }
}

} // namespace uml001
