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
#include "uml001/clock_service_impl.h"
#include "uml001/crypto_utils.h"
#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"

#include <sstream>
#include <iomanip>

namespace uml001 {

ClockServiceImpl::ClockServiceImpl(EventOrchestrator& orchestrator,
                                   BFTQuorumTrustedClock& clock)
    : orchestrator_(orchestrator)
    , clock_(clock)
{}

// ------------------------ GetTime ------------------------

grpc::Status ClockServiceImpl::GetTime(grpc::ServerContext*,
                                       const uml001::GetTimeRequest*,
                                       uml001::TimeResponse* resp)
{
    SignedState event;
    event.set_event_id(pipeline::GRPC_GET_TIME);
    event.set_logical_time_ns(clock_.now_unix() * 1000000000ULL);
    const auto ctx = orchestrator_.ingest_with_context(event);

    resp->set_unix_timestamp(ctx.grpc_unix_time);
    resp->set_drift_applied(ctx.grpc_drift);
    resp->set_last_updated_unix(ctx.grpc_unix_time);
    // De-scoped fields (see proto/clock_service.proto contract notes).
    resp->set_monotonic_version(0);
    resp->set_signature("");
    resp->set_leader_id("local");       // single-node leader id for now
    resp->set_key_id("");
    resp->set_alignment_context_id("");

    return grpc::Status::OK;
}

// ------------------------ GetStatus ------------------------

grpc::Status ClockServiceImpl::GetStatus(grpc::ServerContext*,
                                         const uml001::GetStatusRequest*,
                                         uml001::StatusResponse* resp)
{
    SignedState event;
    event.set_event_id(pipeline::GRPC_GET_STATUS);
    event.set_logical_time_ns(clock_.now_unix() * 1000000000ULL);
    const auto ctx = orchestrator_.ingest_with_context(event);

    resp->set_operational(ctx.grpc_operational);
    resp->set_quorum_threshold(ctx.grpc_quorum_threshold);
    // De-scoped field (see proto/clock_service.proto contract notes).
    resp->set_current_version(0);

    return grpc::Status::OK;
}

// ------------------------ AlignTime ------------------------

grpc::Status ClockServiceImpl::AlignTime(grpc::ServerContext*,
                                         const uml001::AlignTimeRequest* req,
                                         uml001::AlignTimeResponse* resp)
{
    if (!req || req->peer_id().empty() || req->local_anchor().empty()) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "peer_id and local_anchor are required");
    }

    const std::string session_id = make_session_id();

    std::string payload;
    pipeline::encode_align_payload(req->peer_id(), session_id, req->local_anchor(), &payload);
    SignedState event;
    event.set_event_id(pipeline::GRPC_ALIGN_TIME);
    event.set_logical_time_ns(clock_.now_unix() * 1000000000ULL);
    event.set_payload(payload);
    const auto ctx = orchestrator_.ingest_with_context(event);

    // Fill response
    resp->set_session_id(ctx.grpc_align_session_id.empty() ? session_id : ctx.grpc_align_session_id);
    resp->set_remote_anchor(ctx.grpc_align_remote_anchor);
    // De-scoped field (see proto/clock_service.proto contract notes).
    resp->set_signature_proof(std::string());
    resp->set_server_timestamp(ctx.grpc_align_server_ts);

    return grpc::Status::OK;
}

// ------------------------ Helpers ------------------------

std::string ClockServiceImpl::make_session_id() const
{
    // 16 bytes of randomness, hex-encoded
    auto bytes = secure_random_bytes(16);
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

std::string ClockServiceImpl::bytes_to_hex(const std::string& bytes) const
{
    std::ostringstream oss;
    for (unsigned char c : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(c);
    }
    return oss.str();
}

} // namespace uml001
