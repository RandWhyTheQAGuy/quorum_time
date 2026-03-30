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

#include "uml001/default_gossip_provider.h"

int main()
{
    uml001::DefaultGossipProvider provider("node-A", {"node-B"});
    assert(provider.is_external());
    assert(provider.cluster_size() == 2);

    bool got_time = false;
    bool got_prefix = false;
    provider.subscribe("uml001.worker.ntp_sync", [&](const uml001::SignedState& s) {
        got_time = (s.event_id() == "uml001.worker.ntp_sync");
    });
    provider.subscribe("uml001.control.*", [&](const uml001::SignedState& s) {
        got_prefix = (s.event_id() == "uml001.control.hitl.approve");
    });

    uml001::SignedState a;
    a.set_event_id("uml001.worker.ntp_sync");
    provider.broadcast(a);
    assert(got_time);

    uml001::SignedState b;
    b.set_event_id("uml001.control.hitl.approve");
    provider.on_receive(b);
    assert(got_prefix);

    return 0;
}
