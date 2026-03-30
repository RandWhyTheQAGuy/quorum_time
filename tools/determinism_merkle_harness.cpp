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
#include <iostream>
#include <string>

#include "proto/signed_state.pb.h"
#include "MerkleVaultLog.h"

int main() {
    uml001::SignedState s;
    s.set_logical_time_ns(1700000005000000000ULL);
    s.set_event_id("evt.same");
    s.set_key_id("kdet");
    s.set_payload("payload-fixed");
    s.set_signature("sig-fixed");
    auto* g = s.mutable_gossip();
    g->set_hops(3);
    g->set_ttl(5);
    g->set_origin_node_id("node-a");

    uml001::gossip::MerkleVaultLog log;

    const std::string vault_head = "vault-head-fixed";
    const std::string leaf1 = log.compute_leaf(s, vault_head);
    log.append_leaf(leaf1);
    const std::string head1 = log.head();

    const std::string leaf2 = log.compute_leaf(s, vault_head);
    log.append_leaf(leaf2);
    const std::string head2 = log.head();

    std::cout << "leaf1=" << leaf1 << "\n";
    std::cout << "leaf2=" << leaf2 << "\n";
    std::cout << "head1=" << head1 << "\n";
    std::cout << "head2=" << head2 << "\n";

    return 0;
}
