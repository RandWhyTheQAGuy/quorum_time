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
#include "uml001/gossip_dedup.h"
#include "uml001/crypto_utils.h"

namespace uml001::gossip {

GossipDedup::GossipDedup(std::size_t max_entries)
    : max_entries_(max_entries == 0 ? 1 : max_entries) {}

std::string GossipDedup::key_for(const SignedState& msg)
{
    // Include immutable event fingerprint to avoid collapsing distinct events.
    const std::string payload_hash = sha256_hex(msg.payload());
    return msg.event_id() + ":" +
           msg.gossip().origin_node_id() + ":" +
           std::to_string(msg.logical_time_ns()) + ":" +
           msg.key_id() + ":" +
           msg.signature() + ":" +
           payload_hash;
}

bool GossipDedup::is_duplicate(const SignedState& msg) const
{
    std::lock_guard<std::mutex> lock(mu_);
    std::string k = key_for(msg);
    return seen_.count(k) > 0;
}

void GossipDedup::mark_seen(const SignedState& msg)
{
    std::lock_guard<std::mutex> lock(mu_);
    const std::string k = key_for(msg);
    if (seen_.insert(k).second) {
        order_.push_back(k);
        while (order_.size() > max_entries_) {
            seen_.erase(order_.front());
            order_.pop_front();
        }
    }
}

} // namespace uml001::gossip
