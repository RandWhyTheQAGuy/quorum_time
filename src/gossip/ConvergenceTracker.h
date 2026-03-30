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

#include <unordered_map>
#include <unordered_set>
#include <mutex>

#include "proto/signed_state.pb.h"

namespace uml001::gossip {

class ConvergenceTracker {
public:
    void observe(const SignedState& msg);

    bool isConverged(const std::string& event_id) const;

    size_t ackCount(const std::string& event_id) const;

    /// Pipeline path: track merkle leaf + hop for stability heuristic.
    void observe_pipeline(const std::string& merkle_leaf,
                          std::uint32_t hop_count,
                          const std::string& vote_fingerprint);

    bool is_stable() const;

    void seal_epoch();

private:
    mutable std::mutex mu_;

    std::unordered_map<std::string, std::unordered_set<std::string>> acks_;

    std::uint64_t epoch_id_ = 0;
    std::uint32_t epoch_observations_ = 0;
    std::uint32_t epoch_hop_max_ = 0;
    std::unordered_map<std::string, std::uint32_t> leaf_votes_;
    std::unordered_map<std::string, std::unordered_set<std::string>> leaf_vote_fingerprints_;
    std::string stable_leaf_;
    std::uint32_t stable_leaf_votes_ = 0;
    bool stable_ = false;
};

}