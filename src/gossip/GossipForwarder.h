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
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "proto/signed_state.pb.h"
#include "TTLPolicy.h"

namespace uml001::gossip {

class IGossipTransport {
public:
    virtual ~IGossipTransport() = default;
    virtual void send(const std::string& peer_id, const SignedState& msg) = 0;
    virtual std::vector<std::string> peers() const = 0;
};

/// Network transport: inbound messages invoke the ingest handler (typically EventOrchestrator::ingest).
class GossipForwarder {
public:
    GossipForwarder(std::shared_ptr<IGossipTransport> transport,
                    std::shared_ptr<TTLPolicy>        ttl_policy,
                    std::string                       node_id);

    void set_ingest_handler(std::function<void(const SignedState&)> handler);

    void onReceive(const SignedState& msg);

    void send_to_peers(const SignedState& msg);

    const std::string& node_id() const { return node_id_; }

private:
    std::shared_ptr<IGossipTransport> transport_;
    std::shared_ptr<TTLPolicy>        ttl_policy_;
    std::string                       node_id_;

    std::function<void(const SignedState&)> ingest_;
};

} // namespace uml001::gossip
