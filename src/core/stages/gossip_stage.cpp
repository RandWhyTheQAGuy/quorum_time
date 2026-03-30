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
#include "uml001/stages/gossip_stage.h"
#include "GossipForwarder.h"
#include "TTLPolicy.h"
#include <cstdint>

namespace uml001 {

GossipStage::GossipStage(gossip::GossipForwarder* f, gossip::TTLPolicy* p)
    : forwarder_(f), policy_(p) {}

void GossipStage::execute(EventContext& ctx)
{
    if (ctx.aborted || !forwarder_ || !policy_) {
        return;
    }

    const auto& g_in = ctx.event.gossip();

    if (g_in.ttl() == 0 && g_in.hops() == 0 && g_in.origin_node_id().empty()) {
        ctx.gossip_forwarded = false;
        ctx.audit_reason = "gossip_local_noop";
        return;
    }

    const bool has_origin = !g_in.origin_node_id().empty();

    // External gossip must never arrive with zero hops; this blocks TTL/hop reset forgery.
    if (has_origin && g_in.hops() == 0) {
        ctx.gossip_forwarded = false;
        ctx.audit_reason = "gossip_hops_reset_rejected";
        return;
    }

    // Prevent local echo amplification loops.
    if (has_origin && g_in.origin_node_id() == forwarder_->node_id()) {
        ctx.gossip_forwarded = false;
        ctx.audit_reason = "gossip_self_echo_rejected";
        return;
    }

    // Fail closed on overflow to preserve hop monotonicity.
    if (g_in.hops() == UINT32_MAX) {
        ctx.gossip_forwarded = false;
        ctx.audit_reason = "gossip_hops_overflow_rejected";
        return;
    }

    const uint32_t next_hops = g_in.hops() + 1;
    const uint32_t next_ttl  = policy_->decrement(g_in.ttl());
    ctx.hop_count = next_hops;

    GossipState gated;
    gated.set_hops(next_hops);
    gated.set_ttl(next_ttl);
    gated.set_validated(g_in.validated());
    gated.set_origin_node_id(has_origin ? g_in.origin_node_id() : forwarder_->node_id());

    if (!policy_->allow(gated)) {
        ctx.gossip_forwarded = false;
        ctx.audit_reason = "gossip_policy_rejected";
        return;
    }

    // Preserve EventContext event semantics: forward a derived copy without mutating ctx.event.
    SignedState outbound = ctx.event;
    auto* g_out = outbound.mutable_gossip();
    g_out->set_hops(gated.hops());
    g_out->set_ttl(gated.ttl());
    g_out->set_validated(gated.validated());
    g_out->set_origin_node_id(gated.origin_node_id());

    forwarder_->send_to_peers(outbound);

    ctx.gossip_forwarded = true;
}

} // namespace uml001
