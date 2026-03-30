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
#include "uml001/stages/merkle_stage.h"

namespace uml001 {

MerkleStage::MerkleStage(gossip::MerkleVaultLog* log)
    : log_(log) {}

void MerkleStage::execute(EventContext& ctx) {
    if (ctx.aborted || !log_) {
        return;
    }

    // Fail closed: Merkle must bind to the exact vault write for this event.
    if (!ctx.vault_written || ctx.vault_head_after.empty() || ctx.event_hash.empty()) {
        ctx.aborted = true;
        ctx.audit_reason = "vault_binding_missing";
        return;
    }

    // Leaf = deterministic hash of event + vault state
    ctx.merkle_leaf = log_->compute_leaf(ctx.event, ctx.vault_head_after);

    log_->append_leaf(ctx.merkle_leaf);

    // Root is implicitly updated inside log
}

} // namespace uml001