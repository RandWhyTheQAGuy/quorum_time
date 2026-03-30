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
#include <pistache/endpoint.h>
#include <pistache/router.h>

#include <unordered_set>
#include <filesystem>
#include <memory>
#include <string>

#include "uml001/bft_quorum_clock.h"
#include "uml001/event_orchestrator.h"
#include "uml001/pipeline_bootstrap.h"
#include "uml001/rest_handlers.h"
#include "uml001/rest_auth_config.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

using namespace uml001;
using namespace uml001::rest;

int main() {
    // --------------------------------------------------------
    // HTTP server setup
    // --------------------------------------------------------
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(8080));

    auto opts = Pistache::Http::Endpoint::options()
        .threads(2)
        .flags(Pistache::Tcp::Options::ReuseAddr);

    Pistache::Http::Endpoint server(addr);
    server.init(opts);

    Pistache::Rest::Router router;

    // --------------------------------------------------------
    // Clock + Vault wiring
    // --------------------------------------------------------

    BftClockConfig cfg;
    cfg.min_quorum = 3;
    cfg.fail_closed = false;
    std::unordered_set<std::string> authorities = {
        "time.cloudflare.com", "time.google.com", "time.nist.gov"
    };

    OsStrongClock strong_clock;
    SimpleHashProvider hash_provider;

    auto backend = std::make_shared<SimpleFileVaultBackend>(
        std::filesystem::path("/tmp/uml001_dummy_vault") / "vault.log");

    // ColdVault configuration
    ColdVault::Config vault_cfg;
    vault_cfg.base_directory = std::filesystem::path("/tmp/uml001_dummy_vault");
    vault_cfg.max_file_size_bytes = 10 * 1024 * 1024; // 10MB
    vault_cfg.max_file_age_seconds = 86400;           // 24h

    auto vault = std::make_shared<ColdVault>(vault_cfg, backend, strong_clock, hash_provider);

    auto clock = std::make_shared<BFTQuorumTrustedClock>(cfg, authorities, vault);
    ClockGovernor governor(3);
    EventOrchestrator orchestrator(clock.get(), vault.get());
    auto pipeline_runtime = register_default_pipeline(
        orchestrator, *vault, *clock, governor, hash_provider);
    (void)pipeline_runtime;

    // --------------------------------------------------------
    // REST auth + handlers
    // --------------------------------------------------------
    RestAuthConfig auth;
    auth.mode = RestAuthMode::API_KEY;
    auth.api_key = "supersecret";

    TimeApiHandler handler(orchestrator, auth, *vault);
    handler.setup_routes(router);

    server.setHandler(router.handler());
    server.serve();

    return 0;
}
