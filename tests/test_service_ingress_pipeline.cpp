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
#include <memory>
#include <type_traits>
#include <unordered_set>

#include "clock_service.grpc.pb.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/clock_service_impl.h"
#include "uml001/event_orchestrator.h"
#include "uml001/governor.h"
#include "uml001/pipeline_bootstrap.h"
#include "uml001/rest_auth_config.h"
#include "uml001/rest_handlers.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

int main()
{
    // Constructor contract guard: service ingress must depend on orchestrator.
    static_assert(std::is_constructible_v<
                  uml001::ClockServiceImpl,
                  uml001::EventOrchestrator&, uml001::BFTQuorumTrustedClock&>);
    static_assert(!std::is_constructible_v<
                  uml001::ClockServiceImpl,
                  uml001::BFTQuorumTrustedClock&, uml001::ColdVault&,
                  uml001::ClockGovernor&, uml001::IHashProvider&>);

    static_assert(std::is_constructible_v<
                  uml001::rest::TimeApiHandler,
                  uml001::EventOrchestrator&, uml001::RestAuthConfig, uml001::ColdVault&>);
    static_assert(!std::is_constructible_v<
                  uml001::rest::TimeApiHandler,
                  std::shared_ptr<uml001::BFTQuorumTrustedClock>, uml001::RestAuthConfig,
                  uml001::ColdVault&>);

    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "quorum_time_test_service_ingress";
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
    (void)runtime;

    uml001::ClockServiceImpl service(orchestrator, clock);

    uml001::GetTimeRequest req;
    uml001::TimeResponse time_resp;
    auto status = service.GetTime(nullptr, &req, &time_resp);
    assert(status.ok());
    assert(time_resp.unix_timestamp() > 0);
    assert(time_resp.monotonic_version() == 0);
    assert(time_resp.signature().empty());
    assert(time_resp.key_id().empty());
    assert(time_resp.alignment_context_id().empty());

    uml001::GetStatusRequest status_req;
    uml001::StatusResponse status_resp;
    status = service.GetStatus(nullptr, &status_req, &status_resp);
    assert(status.ok());
    assert(status_resp.current_version() == 0);

    uml001::AlignTimeRequest align_req;
    align_req.set_peer_id("peer-a");
    align_req.set_local_anchor("abc");
    uml001::AlignTimeResponse align_resp;
    status = service.AlignTime(nullptr, &align_req, &align_resp);
    assert(status.ok());
    assert(!align_resp.session_id().empty());
    assert(align_resp.signature_proof().empty());
    assert(align_resp.server_timestamp() > 0);

    return 0;
}
