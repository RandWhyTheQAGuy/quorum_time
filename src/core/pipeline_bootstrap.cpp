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
#include "uml001/pipeline_bootstrap.h"

#include "ConvergenceTracker.h"
#include "GossipForwarder.h"
#include "MerkleVaultLog.h"
#include "TTLPolicy.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/stages/convergence_stage.h"
#include "uml001/stages/gossip_stage.h"
#include "uml001/stages/merkle_stage.h"
#include "uml001/stages/passport_validation_stage.h"
#include "uml001/stages/quorum_stage.h"
#include "uml001/stages/shared_state_ingress_stage.h"
#include "uml001/stages/vault_stage.h"

namespace uml001 {

namespace {

class NullGossipTransport final : public gossip::IGossipTransport {
public:
    void send(const std::string&, const SignedState&) override {}
    std::vector<std::string> peers() const override { return {}; }
};

} // namespace

PipelineBootstrapRuntime register_default_pipeline(
    EventOrchestrator& orchestrator,
    ColdVault& vault,
    BFTQuorumTrustedClock& clock,
    ClockGovernor& governor,
    IHashProvider& hash_provider,
    std::shared_ptr<gossip::IGossipTransport> transport,
    const std::string& node_id)
{
    PipelineBootstrapRuntime runtime;
    runtime.dedup = std::make_unique<gossip::GossipDedup>();
    runtime.ttl_policy = std::make_shared<gossip::TTLPolicy>();
    runtime.transport = transport ? std::move(transport)
                                  : std::make_shared<NullGossipTransport>();
    runtime.forwarder = std::make_unique<gossip::GossipForwarder>(
        runtime.transport, runtime.ttl_policy, node_id);
    runtime.merkle_log = std::make_unique<gossip::MerkleVaultLog>();
    runtime.convergence_tracker = std::make_unique<gossip::ConvergenceTracker>();

    runtime.forwarder->set_ingest_handler(
        [&orchestrator](const SignedState& msg) { orchestrator.ingest(msg); });

    orchestrator.register_stage(
        std::make_unique<PassportValidationStage>(runtime.dedup.get()));
    orchestrator.register_stage(
        std::make_unique<SharedStateIngressStage>());
    orchestrator.register_stage(
        std::make_unique<VaultStage>(&vault));
    orchestrator.register_stage(
        std::make_unique<GossipStage>(runtime.forwarder.get(), runtime.ttl_policy.get()));
    orchestrator.register_stage(
        std::make_unique<MerkleStage>(runtime.merkle_log.get()));
    orchestrator.register_stage(
        std::make_unique<ConvergenceStage>(runtime.convergence_tracker.get()));
    orchestrator.register_stage(
        std::make_unique<QuorumStage>(&clock, &governor, &hash_provider));

    return runtime;
}

} // namespace uml001
