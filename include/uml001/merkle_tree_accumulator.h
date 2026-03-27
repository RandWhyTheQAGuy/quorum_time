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
#include "crypto_interfaces.h"
#include <vector>

namespace uml001 {

class MerkleAccumulator {
public:
    explicit MerkleAccumulator(IHashProvider& hash)
        : hash_(hash) {}

    void add_leaf(const std::string& data) {
        leaves_.push_back(hash_.sha256(data));
    }

    std::string root() {
        if (leaves_.empty()) return "EMPTY";

        std::vector<std::string> level = leaves_;
        while (level.size() > 1) {
            std::vector<std::string> next;
            for (size_t i = 0; i < level.size(); i += 2) {
                if (i + 1 < level.size())
                    next.push_back(hash_.sha256(level[i] + level[i+1]));
                else
                    next.push_back(level[i]);
            }
            level = next;
        }
        return level[0];
    }

private:
    IHashProvider& hash_;
    std::vector<std::string> leaves_;
};

}