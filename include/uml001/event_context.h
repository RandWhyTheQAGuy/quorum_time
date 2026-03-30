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

#include <string>
#include <cstdint>
#include <optional>
#include <vector>
#include "proto/signed_state.pb.h"
#include "uml001/bft_quorum_clock.h"

namespace uml001 {

// ============================================================
// EventContext (Single-owner execution envelope per ingest)
// ============================================================

struct EventContext {
    SignedState event;

    // Derived deterministic metadata
    std::string event_hash;
    std::string merkle_leaf;
    std::string vault_head_before;
    std::string vault_head_after;

    uint64_t received_at_ns = 0;
    uint64_t processed_at_ns = 0;

    // Gossip lineage tracking
    uint32_t hop_count = 0;
    bool is_converged = false;

    // Execution flags
    bool vault_written = false;
    bool gossip_forwarded = false;
    bool quorum_updated = false;

    /// Set by PassportValidationStage when duplicate gossip or invalid passport
    bool aborted = false;
    std::string audit_stage;
    std::string audit_reason;

    // --- gRPC / REST response scratch (filled by QuorumStage for read/control events)
    uint64_t grpc_unix_time = 0;
    int64_t grpc_drift = 0;
    uint32_t grpc_quorum_threshold = 0;
    bool grpc_operational = true;

    std::string grpc_align_session_id;
    std::string grpc_align_remote_anchor;
    uint64_t grpc_align_server_ts = 0;

    std::optional<BftSyncResult> rest_sync_result;
    bool rest_shared_state_ok = false;
};

} // namespace uml001