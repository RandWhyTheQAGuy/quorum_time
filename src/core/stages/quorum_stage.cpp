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
#include "uml001/stages/quorum_stage.h"

#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"

#include <iomanip>
#include <sstream>

namespace uml001 {

namespace {

std::string bytes_to_hex_local(const std::string& bytes)
{
    std::ostringstream oss;
    for (unsigned char c : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(c);
    }
    return oss.str();
}

} // namespace

QuorumStage::QuorumStage(BFTQuorumTrustedClock* clock,
                           ClockGovernor*         governor,
                           IHashProvider*         hash_provider)
    : clock_(clock)
    , governor_(governor)
    , hash_(hash_provider) {}

void QuorumStage::execute(EventContext& ctx)
{
    if (ctx.aborted || !clock_ || !governor_ || !hash_) {
        return;
    }

    const std::string& id = ctx.event.event_id();
    const std::string& payload = ctx.event.payload();

    const uint64_t event_unix_time = ctx.event.logical_time_ns() / 1000000000ULL;

    if (id == pipeline::GRPC_GET_TIME) {
        ctx.grpc_unix_time = event_unix_time;
        ctx.grpc_drift     = clock_->get_current_drift();
        ctx.quorum_updated = true;
        return;
    }

    if (id == pipeline::GRPC_GET_STATUS) {
        ctx.grpc_quorum_threshold =
            static_cast<uint32_t>(governor_->required());
        ctx.grpc_operational = true;
        ctx.quorum_updated   = true;
        return;
    }

    if (id == pipeline::GRPC_ALIGN_TIME) {
        std::string peer_id;
        std::string session_id;
        std::string local_anchor;
        if (!pipeline::decode_align_payload(payload, peer_id, session_id, local_anchor)) {
            ctx.audit_reason = "align_payload_decode_failed";
            return;
        }
        const std::string local_anchor_hex = bytes_to_hex_local(local_anchor);
        const std::string remote_anchor_hex  = hash_->sha256(local_anchor_hex);

        ctx.grpc_align_session_id   = session_id;
        ctx.grpc_align_remote_anchor = remote_anchor_hex;
        ctx.grpc_align_server_ts     = event_unix_time;
        ctx.quorum_updated           = true;
        return;
    }

    if (id == pipeline::REST_TIME_NOW) {
        ctx.grpc_unix_time = event_unix_time;
        ctx.grpc_drift     = clock_->get_current_drift();
        ctx.quorum_updated = true;
        return;
    }

    if (id == pipeline::WORKER_NTP_SYNC) {
        if (!ctx.is_converged) {
            ctx.quorum_updated = false;
            ctx.audit_reason = "worker_sync_not_converged";
            return;
        }
        std::vector<TimeObservation> observations;
        double warp_score = 0.0;
        if (!pipeline::decode_ntp_sync_payload(payload, observations, warp_score)) {
            ctx.quorum_updated = false;
            ctx.audit_reason = "worker_sync_payload_decode_failed";
            return;
        }
        auto res = clock_->update_and_sync(observations, warp_score);
        if (!res.has_value()) {
            ctx.quorum_updated = false;
            ctx.audit_reason = "worker_sync_quorum_rejected";
            return;
        }
        ctx.rest_sync_result = *res;
        ctx.quorum_updated = true;
        return;
    }

    if (id == pipeline::INTERNAL_SHARED_STATE_APPLY) {
        if (!ctx.is_converged) {
            ctx.quorum_updated = false;
            ctx.rest_shared_state_ok = false;
            ctx.audit_reason = "shared_state_not_converged";
            return;
        }

        uint64_t monotonic_version = 0;
        double warp_score = 0.0;
        uint64_t shared_agreed_time = 0;
        int64_t shared_applied_drift = 0;
        uint64_t leader_system_time_at_sync = 0;
        std::string signature_hex;
        std::string leader_id;
        std::string key_id;

        if (!pipeline::decode_shared_state_payload(payload,
                                                   monotonic_version,
                                                   warp_score,
                                                   shared_agreed_time,
                                                   shared_applied_drift,
                                                   leader_system_time_at_sync,
                                                   signature_hex,
                                                   leader_id,
                                                   key_id)) {
            ctx.quorum_updated = false;
            ctx.rest_shared_state_ok = false;
            ctx.audit_reason = "shared_state_payload_decode_failed";
            return;
        }

        // apply_shared_state verifies a signature payload that includes warp_score;
        // this binds drift policy inputs to the signed envelope.
        const bool ok = clock_->apply_shared_state(shared_agreed_time,
                                                   shared_applied_drift,
                                                   leader_system_time_at_sync,
                                                   signature_hex,
                                                   leader_id,
                                                   key_id,
                                                   monotonic_version,
                                                   warp_score);
        ctx.rest_shared_state_ok = ok;
        ctx.quorum_updated = ok;
        if (!ok) {
            ctx.audit_reason = "shared_state_apply_rejected";
        }
        return;
    }

    if (id == pipeline::REST_TIME_SYNC || id == pipeline::REST_TIME_SHARED_STATE) {
        // External and worker-originated control inputs must never mutate BFT state directly.
        // Quorum updates are reserved for convergence-gated internal transitions only.
        ctx.quorum_updated = false;
        ctx.rest_shared_state_ok = false;
        ctx.audit_reason = "direct_quorum_mutation_blocked";
        return;
    }

    if (!ctx.is_converged) {
        ctx.quorum_updated = false;
    }
}

} // namespace uml001
