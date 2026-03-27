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

#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include "bft_quorum_clock.h"
#include "rest_auth_config.h"

namespace uml001::rest {

/**
 * @brief REST handler for the UML-001 Trusted Time API.
 *
 * Endpoints:
 *   - GET  /time/now
 *   - POST /time/sync
 *   - POST /time/shared-state
 *
 * All endpoints enforce authentication and log:
 *   - Auth failures
 *   - Sync failures
 *   - Shared-state rejections
 *   - Successful operations
 */
class TimeApiHandler {
public:
    TimeApiHandler(
        std::shared_ptr<BFTQuorumTrustedClock> clock,
        RestAuthConfig                         auth_config,
        ColdVault&                             vault
    );

    void setup_routes(Pistache::Rest::Router& router);

private:
    bool check_auth(const Pistache::Rest::Request& req,
                    const std::string& endpoint_name,
                    std::string&       failure_reason);

    void handle_now(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    void handle_sync(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    void handle_shared_state(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    std::shared_ptr<BFTQuorumTrustedClock> clock_;
    RestAuthConfig                         auth_;
    ColdVault&                             vault_;
};

} // namespace uml001::rest
