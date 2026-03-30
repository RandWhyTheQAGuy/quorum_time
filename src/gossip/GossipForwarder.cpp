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
#include "GossipForwarder.h"
#include <algorithm>

namespace uml001::gossip {

GossipForwarder::GossipForwarder(
    std::shared_ptr<IGossipTransport> transport,
    std::shared_ptr<TTLPolicy>        ttl_policy,
    std::string                       node_id)
    : transport_(std::move(transport)),
      ttl_policy_(std::move(ttl_policy)),
      node_id_(std::move(node_id)) {}

void GossipForwarder::set_ingest_handler(std::function<void(const SignedState&)> handler)
{
    ingest_ = std::move(handler);
}

void GossipForwarder::onReceive(const SignedState& msg)
{
    if (ingest_) {
        ingest_(msg);
    }
}

void GossipForwarder::send_to_peers(const SignedState& msg)
{
    if (!transport_) {
        return;
    }
    auto peers = transport_->peers();
    std::sort(peers.begin(), peers.end());
    for (const auto& peer : peers) {
        transport_->send(peer, msg);
    }
}

} // namespace uml001::gossip
