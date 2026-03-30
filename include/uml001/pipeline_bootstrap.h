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

#include <memory>
#include <string>

#include "uml001/event_orchestrator.h"
#include "uml001/gossip_dedup.h"
#include "uml001/governor.h"
#include "ConvergenceTracker.h"
#include "GossipForwarder.h"
#include "MerkleVaultLog.h"
#include "TTLPolicy.h"

namespace uml001 {

class BFTQuorumTrustedClock;
class IHashProvider;
class ColdVault;

struct PipelineBootstrapRuntime {
    std::unique_ptr<gossip::GossipDedup> dedup;
    std::shared_ptr<gossip::TTLPolicy> ttl_policy;
    std::shared_ptr<gossip::IGossipTransport> transport;
    std::unique_ptr<gossip::GossipForwarder> forwarder;
    std::unique_ptr<gossip::MerkleVaultLog> merkle_log;
    std::unique_ptr<gossip::ConvergenceTracker> convergence_tracker;
};

PipelineBootstrapRuntime register_default_pipeline(
    EventOrchestrator& orchestrator,
    ColdVault& vault,
    BFTQuorumTrustedClock& clock,
    ClockGovernor& governor,
    IHashProvider& hash_provider,
    std::shared_ptr<gossip::IGossipTransport> transport = nullptr,
    const std::string& node_id = "local");

} // namespace uml001
