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
#pragma once
/**
 * sidecar.h
 *
 * BFT Trusted Clock — HTTP Sidecar Interface
 * ==========================================
 * Declares the public-facing components used by main_sidecar.cpp:
 *
 *  - run_sidecar_sync_loop(): background NTP/BFT sync thread
 *  - SidecarConfig: runtime configuration for the sidecar
 *
 * This header intentionally avoids pulling in heavy dependencies
 * (httplib, nlohmann/json, etc.) to keep compile boundaries clean.
 */

#include <memory>
#include <atomic>
#include <unordered_set>
#include <string>

namespace uml001 {

class BFTQuorumTrustedClock;
class NtpObservationFetcher;

/**
 * SidecarConfig
 *
 * Runtime configuration for the BFT clock sidecar.
 * These values are typically injected via environment variables
 * or Kubernetes ConfigMaps.
 */
struct SidecarConfig {
    int     sync_interval_s   = 60;     // How often to run BFT sync
    int     max_total_drift_s = 3600;   // Drift threshold for /health
    int     http_port         = 9090;   // Local REST API port
    bool    bind_localhost    = true;   // Restrict to 127.0.0.1
};

/**
 * run_sidecar_sync_loop()
 *
 * Background thread that:
 *   - Fetches NTP observations
 *   - Runs BFT consensus
 *   - Applies drift updates
 *   - Logs sync results
 *
 * The loop exits when `shutdown` becomes true.
 */
void run_sidecar_sync_loop(
    std::shared_ptr<BFTQuorumTrustedClock> clock,
    std::shared_ptr<NtpObservationFetcher> fetcher,
    std::atomic<bool>& shutdown);

} // namespace uml001
