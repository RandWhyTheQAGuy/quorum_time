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
#include "MerkleVaultLog.h"
#include "uml001/crypto_utils.h"

namespace uml001::gossip {

std::string MerkleVaultLog::hash(const VaultEntry& entry) const {
    std::string serialized;
    if (!entry.state.SerializeToString(&serialized)) {
        return sha256_hex(entry.prev_hash + "|SERIALIZE_ERROR");
    }
    const std::string event_hash = sha256_hex(serialized);
    return sha256_hex(entry.prev_hash + "|" + event_hash);
}

void MerkleVaultLog::append(const SignedState& state) {
    std::lock_guard<std::mutex> lock(mu_);

    VaultEntry entry;
    entry.state = state;
    entry.prev_hash = head_;
    entry.hash = hash(entry);

    chain_.push_back(entry);
    head_ = entry.hash;
}

std::string MerkleVaultLog::head() const {
    std::lock_guard<std::mutex> lock(mu_);
    return head_;
}

std::string MerkleVaultLog::compute_leaf(const SignedState& state,
                                         const std::string& vault_head_after) const
{
    std::string serialized;
    if (!state.SerializeToString(&serialized)) {
        return sha256_hex(vault_head_after + "|SERIALIZE_ERROR");
    }
    const std::string event_hash = sha256_hex(serialized);
    return sha256_hex(vault_head_after + "|" + event_hash);
}

void MerkleVaultLog::append_leaf(const std::string& leaf)
{
    std::lock_guard<std::mutex> lock(mu_);

    VaultEntry entry;
    entry.state.Clear();
    entry.prev_hash = head_;
    // Chain head depends on prior head + leaf to preserve deterministic ordering.
    entry.hash = sha256_hex(entry.prev_hash + "|" + leaf);
    chain_.push_back(entry);
    head_ = entry.hash;
}

} // namespace uml001::gossip