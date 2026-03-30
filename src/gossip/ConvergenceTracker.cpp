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
#include "ConvergenceTracker.h"

namespace uml001::gossip {
namespace {
constexpr std::size_t kMinAckVotes = 3;
constexpr std::uint32_t kMinLeafVotes = 3;
}

void ConvergenceTracker::observe(const SignedState& msg) {
    std::lock_guard<std::mutex> lock(mu_);

    auto& set = acks_[msg.event_id()];
    set.insert(msg.gossip().origin_node_id());
}

bool ConvergenceTracker::isConverged(const std::string& event_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = acks_.find(event_id);
    if (it == acks_.end()) return false;

    return it->second.size() >= kMinAckVotes;
}

size_t ConvergenceTracker::ackCount(const std::string& event_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = acks_.find(event_id);
    if (it == acks_.end()) return 0;
    return it->second.size();
}

void ConvergenceTracker::observe_pipeline(const std::string& merkle_leaf,
                                          std::uint32_t hop_count,
                                          const std::string& vote_fingerprint)
{
    std::lock_guard<std::mutex> lock(mu_);
    if (merkle_leaf.empty() || vote_fingerprint.empty()) {
        stable_ = false;
        return;
    }

    auto& fingerprints = leaf_vote_fingerprints_[merkle_leaf];
    const bool is_new_vote = fingerprints.insert(vote_fingerprint).second;
    if (is_new_vote) {
        ++epoch_observations_;
        if (hop_count > epoch_hop_max_) {
            epoch_hop_max_ = hop_count;
        }
        auto& votes = leaf_votes_[merkle_leaf];
        if (votes < UINT32_MAX) {
            ++votes;
        }
    }

    // Deterministic winner selection for tied vote counts.
    std::string leader_leaf;
    std::uint32_t leader_votes = 0;
    for (const auto& kv : leaf_votes_) {
        if (kv.second > leader_votes ||
            (kv.second == leader_votes && (leader_leaf.empty() || kv.first < leader_leaf))) {
            leader_leaf = kv.first;
            leader_votes = kv.second;
        }
    }
    stable_leaf_ = leader_leaf;
    stable_leaf_votes_ = leader_votes;

    // Epoch + leaf-bound convergence:
    // - leaf must reach quorum vote threshold
    // - leaf must hold strict majority within epoch observations
    // - at least one hop observed (prevents local-only false stability)
    stable_ = (stable_leaf_votes_ >= kMinLeafVotes) &&
              (stable_leaf_votes_ * 2 > epoch_observations_) &&
              (epoch_hop_max_ > 0);
}

bool ConvergenceTracker::is_stable() const
{
    std::lock_guard<std::mutex> lock(mu_);
    return stable_;
}

void ConvergenceTracker::seal_epoch()
{
    std::lock_guard<std::mutex> lock(mu_);
    ++epoch_id_;
    epoch_observations_ = 0;
    epoch_hop_max_ = 0;
    leaf_votes_.clear();
    leaf_vote_fingerprints_.clear();
    stable_leaf_.clear();
    stable_leaf_votes_ = 0;
    stable_ = false;
}

} // namespace uml001::gossip