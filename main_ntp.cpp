/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine‑resilient trusted‑time
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
 *   - BFT Quorum Time: multi‑authority, tamper‑evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross‑domain alignment (AlignTime).
 *
 *   - Transparency Logging: append‑only, hash‑chained audit records
 *                           for time events, alignment proofs, and
 *                           key‑rotation operations.
 *
 *   - Semantic Passports: optional identity and capability metadata
 *                         for systems that require verifiable agent
 *                         provenance and authorization context.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security‑critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open‑source project with a focus on
 * clarity, auditability, and long‑term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community‑driven evolution of verifiable time and
 * distributed trust standards.
 */
/**
 * @file main_ntp.cpp
 * @brief Production-grade Aegis BFT trusted clock daemon with CLI flags and test-safe defaults.
 */

#include "uml001/strong_clock.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/vault.h"
#include "uml001/crypto_utils.h"
#include "uml001/vault_logger.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/governor.h"
#include "uml001/clock_service_impl.h"
#include "uml001/event_orchestrator.h"
#include "uml001/pipeline_bootstrap.h"
#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"

#include <grpcpp/grpcpp.h>
#include "clock_service.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>
#include <unordered_set>
#include <memory>

namespace fs = std::filesystem;

// ============================================================
// CLI CONFIG
// ============================================================

struct Config {
    std::string data_dir  = "./data";
    std::string grpc_addr = "0.0.0.0:50051";
    bool insecure_dev     = false;
};

Config parse_args(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--data-dir" && i + 1 < argc) {
            cfg.data_dir = argv[++i];
        } else if (arg == "--grpc-addr" && i + 1 < argc) {
            cfg.grpc_addr = argv[++i];
        } else if (arg == "--insecure-dev") {
            cfg.insecure_dev = true;
        }
    }
    return cfg;
}

// ============================================================
// SIGNAL HANDLING
// ============================================================

std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true);
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char** argv) {
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto cfg = parse_args(argc, argv);
    fs::path data_dir_path = cfg.data_dir;

    std::cout << "[INIT] Starting Aegis Clock\n";
    std::cout << "[INIT] Data dir: " << data_dir_path.string() << "\n";

    try {
        fs::create_directories(data_dir_path);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Failed to create data dir: " << e.what() << "\n";
        return 1;
    }

    // Core components
    uml001::OsStrongClock    strong_clock;
    uml001::SimpleHashProvider hash_provider;

    // Vault setup
    uml001::ColdVault::Config vault_cfg;
    vault_cfg.base_directory = data_dir_path;

    auto backend   = std::make_shared<uml001::SimpleFileVaultBackend>(data_dir_path / "vault.log");
    auto vault_ptr = std::make_shared<uml001::ColdVault>(vault_cfg, backend, strong_clock, hash_provider);

    uml001::set_vault_logger([vault_ptr](const std::string& k, const std::string& v) {
        vault_ptr->log_security_event(k, v);
    });

    std::unordered_set<std::string> authorities = {
        "time.cloudflare.com",
        "time.google.com",
        "time.nist.gov"
    };

    uml001::BftClockConfig cfg_bft;
    cfg_bft.min_quorum  = 3;
    cfg_bft.fail_closed = !cfg.insecure_dev;

    uml001::BFTQuorumTrustedClock clock(cfg_bft, authorities, vault_ptr);

    std::vector<uml001::NtpServerEntry> servers = {
        { "time.cloudflare.com", 1000, 2000 },
        { "time.google.com",     1000, 2000 },
        { "time.nist.gov",       1000, 2000 }
    };

    uml001::NtpObservationFetcher fetcher("", "", servers, 3, 15, 5);
    uml001::ClockGovernor         governor(5);
    uml001::EventOrchestrator orchestrator(&clock, vault_ptr.get());
    auto pipeline_runtime = uml001::register_default_pipeline(
        orchestrator, *vault_ptr, clock, governor, hash_provider);

    // ========================================================
    // gRPC SERVER
    // ========================================================

    uml001::ClockServiceImpl service(orchestrator, clock);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(cfg.grpc_addr, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();
    std::cout << "[RPC] Listening on " << cfg.grpc_addr << "\n";

    // ========================================================
    // BACKGROUND THREAD
    // ========================================================

    std::thread worker([&]() {
        while (!g_shutdown.load()) {
            try {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto observations = fetcher.fetch();
                if (observations.empty()) {
                    continue;
                }
                std::string payload;
                uml001::pipeline::encode_ntp_sync_payload(observations, 0.0, &payload);
                uml001::SignedState event;
                event.set_event_id(uml001::pipeline::WORKER_NTP_SYNC);
                event.set_logical_time_ns(clock.now_unix() * 1000000000ULL);
                event.set_payload(payload);
                orchestrator.ingest(event);
            } catch (...) {
                uml001::vault_log("error", "background loop failure");
            }
        }
    });

    // ========================================================
    // WAIT LOOP
    // ========================================================

    while (!g_shutdown.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "[SHUTDOWN]\n";
    server->Shutdown();
    worker.join();

    return 0;
}
