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
#include <string>

#include "uml001/gossip_dedup.h"
#include "uml001/crypto_utils.h"
#include "proto/signed_state.pb.h"
#include "ConvergenceTracker.h"

int main()
{
    using uml001::SignedState;
    using uml001::gossip::ConvergenceTracker;
    using uml001::gossip::GossipDedup;

    // Dedup: different payload/signature for same (event_id, origin) must not collide.
    {
        GossipDedup dedup(16);

        SignedState a;
        a.set_event_id("uml001.worker.ntp_sync");
        a.mutable_gossip()->set_origin_node_id("node-a");
        a.set_payload("payload-A");
        a.set_signature("sig-A");
        a.set_logical_time_ns(100);

        SignedState b = a;
        b.set_payload("payload-B");
        b.set_signature("sig-B");
        b.set_logical_time_ns(101);

        dedup.mark_seen(a);
        assert(dedup.is_duplicate(a));
        assert(!dedup.is_duplicate(b));
        dedup.mark_seen(b);
        assert(dedup.is_duplicate(b));
    }

    // Dedup: bounded retention evicts oldest key deterministically.
    {
        GossipDedup dedup(2);
        SignedState a;
        a.set_event_id("e");
        a.mutable_gossip()->set_origin_node_id("o");
        a.set_payload("a");
        a.set_signature("sa");
        a.set_logical_time_ns(1);

        SignedState b = a;
        b.set_payload("b");
        b.set_signature("sb");
        b.set_logical_time_ns(2);

        SignedState c = a;
        c.set_payload("c");
        c.set_signature("sc");
        c.set_logical_time_ns(3);

        dedup.mark_seen(a);
        dedup.mark_seen(b);
        dedup.mark_seen(c); // evicts a
        assert(!dedup.is_duplicate(a));
        assert(dedup.is_duplicate(b));
        assert(dedup.is_duplicate(c));
    }

    // Convergence uniqueness: repeated same fingerprint should count once.
    {
        ConvergenceTracker tracker;
        const std::string leaf = "leaf-1";
        const std::uint32_t hop = 1;

        tracker.observe_pipeline(leaf, hop, "origin-A:event-1");
        tracker.observe_pipeline(leaf, hop, "origin-A:event-1");
        tracker.observe_pipeline(leaf, hop, "origin-A:event-1");
        assert(!tracker.is_stable());

        tracker.observe_pipeline(leaf, hop, "origin-B:event-2");
        assert(!tracker.is_stable());

        tracker.observe_pipeline(leaf, hop, "origin-C:event-3");
        assert(tracker.is_stable());
    }

    // Malformed signature hex must fail verification without throwing.
    {
        const std::string key_hex = uml001::generate_random_bytes_hex(32);
        uml001::register_hmac_authority("auth-A", "k1", key_hex);
        const bool ok = uml001::crypto_verify("payload", "not-hex!", "auth-A", "k1");
        assert(!ok);
    }

    return 0;
}
