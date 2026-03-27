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

#include <string>
#include <vector>

/**
 * @file rest_auth_config.h
 * @brief Authentication configuration for the UML-001 Trusted Time REST API.
 *
 * SECURITY OVERVIEW
 * -----------------
 * UML-001 supports three authentication modes:
 *
 *   1. NONE
 *      - No authentication.
 *      - Only acceptable for isolated CI, local development, or air-gapped test rigs.
 *      - All requests are still logged for audit visibility.
 *
 *   2. API_KEY
 *      - Shared secret provided via HTTP header "X-API-Key".
 *      - Simple to deploy but coarse-grained.
 *      - Compromise of the key grants full access.
 *      - Must be rotated regularly and stored in a secure secret manager.
 *
 *   3. MTLS
 *      - Strongest option.
 *      - Requires TLS termination by a trusted reverse proxy (Envoy, NGINX, HAProxy)
 *        that validates client certificates and injects "X-Client-Identity".
 *      - Identity is cryptographically bound to the client certificate.
 *      - Revocation and rotation handled by PKI.
 *
 * All authentication failures are logged via ColdVault::log_security_event().
 */

namespace uml001 {

enum class RestAuthMode {
    NONE,
    API_KEY,
    MTLS
};

struct RestAuthConfig {
    RestAuthMode mode = RestAuthMode::NONE;

    // Used only in API_KEY mode.
    std::string api_key;

    // Used only in MTLS mode.
    std::vector<std::string> allowed_identities;
};

} // namespace uml001
