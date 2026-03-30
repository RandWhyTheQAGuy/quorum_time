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
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_set>

#include "uml001/bft_quorum_clock.h"
#include "uml001/event_orchestrator.h"
#include "uml001/governor.h"
#include "uml001/pipeline_bootstrap.h"
#include "uml001/pipeline_event_ids.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

int main()
{
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "quorum_time_test_pipeline_wiring";
    fs::create_directories(dir);

    uml001::OsStrongClock strong_clock;
    uml001::SimpleHashProvider hash_provider;
    auto backend = std::make_shared<uml001::SimpleFileVaultBackend>(dir / "vault.log");
    uml001::ColdVault::Config vault_cfg;
    vault_cfg.base_directory = dir;
    auto vault = std::make_shared<uml001::ColdVault>(vault_cfg, backend, strong_clock, hash_provider);

    std::unordered_set<std::string> authorities = {
        "time.cloudflare.com", "time.google.com", "time.nist.gov"
    };
    uml001::BftClockConfig cfg;
    cfg.min_quorum = 3;
    cfg.fail_closed = false;
    uml001::BFTQuorumTrustedClock clock(cfg, authorities, vault);
    uml001::ClockGovernor governor(3);

    uml001::EventOrchestrator orchestrator(&clock, vault.get());
    auto runtime = uml001::register_default_pipeline(orchestrator, *vault, clock, governor, hash_provider);

    uml001::SignedState e;
    const uint64_t ts = clock.now_unix();
    e.set_event_id(uml001::pipeline::GRPC_GET_TIME);
    e.set_logical_time_ns(ts * 1000000000ULL);
    orchestrator.ingest(e);
    const auto ctx = orchestrator.last_context_snapshot();

    assert(!ctx.aborted);
    assert(ctx.vault_written);
    assert(!ctx.vault_head_after.empty());
    assert(!ctx.merkle_leaf.empty());
    assert(ctx.quorum_updated);
    assert(ctx.grpc_unix_time == ts);

    // Order signal: QuorumStage must observe convergence flag from earlier stages.
    uml001::SignedState sync;
    sync.set_event_id(uml001::pipeline::WORKER_NTP_SYNC);
    sync.set_logical_time_ns(ts * 1000000000ULL);
    sync.set_payload("bad");
    orchestrator.ingest(sync);
    const auto sync_ctx = orchestrator.last_context_snapshot();
    assert(sync_ctx.audit_reason == "worker_sync_not_converged");

    std::cout << "test_pipeline_wiring: PASS\n";
    return 0;
}
