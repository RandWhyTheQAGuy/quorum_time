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
#include "uml001/vault_logger.h"

#include <sstream>
#include <iomanip>

namespace uml001 {

ClockServiceImpl::ClockServiceImpl(BFTQuorumTrustedClock& clock,
                                   ColdVault&             vault,
                                   ClockGovernor&         governor,
                                   IHashProvider&         hash_provider)
    : clock_(clock)
    , vault_(vault)
    , governor_(governor)
    , hash_(hash_provider)
{}

// ------------------------ GetTime ------------------------

grpc::Status ClockServiceImpl::GetTime(grpc::ServerContext*,
                                       const uml001::GetTimeRequest*,
                                       uml001::TimeResponse* resp)
{
    const uint64_t now = clock_.now_unix();
    const int64_t  drift = clock_.get_current_drift();

    resp->set_unix_timestamp(now);
    resp->set_drift_applied(drift);
    resp->set_last_updated_unix(now);
    resp->set_monotonic_version(0);      // reserved for future monotonic versioning
    resp->set_signature("");            // reserved for future signing
    resp->set_leader_id("local");       // single-node leader id for now
    resp->set_key_id("");               // reserved for future key binding
    resp->set_alignment_context_id(""); // reserved for future alignment context

    return grpc::Status::OK;
}

// ------------------------ GetStatus ------------------------

grpc::Status ClockServiceImpl::GetStatus(grpc::ServerContext*,
                                         const uml001::GetStatusRequest*,
                                         uml001::StatusResponse* resp)
{
    // For now, operational if we can read a time value at all.
    const uint64_t now = clock_.now_unix();
    (void)now;

    resp->set_operational(true);
    resp->set_quorum_threshold(static_cast<uint32_t>(governor_.required()));
    resp->set_current_version(0); // reserved for future shared-state versioning

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

    const uint64_t server_ts = clock_.now_unix();
    const std::string session_id = make_session_id();

    // Derive a simple server-side anchor from the peer's anchor.
    // This is intentionally deterministic and hash-based so both
    // sides can reason about the relationship between anchors.
    const std::string local_anchor_bytes = req->local_anchor();
    const std::string local_anchor_hex   = bytes_to_hex(local_anchor_bytes);
    const std::string remote_anchor_hex  = hash_.sha256(local_anchor_hex);

    // Fill response
    resp->set_session_id(session_id);
    resp->set_remote_anchor(std::string(
        reinterpret_cast<const char*>(remote_anchor_hex.data()),
        remote_anchor_hex.size()));
    resp->set_signature_proof(std::string()); // reserved for future signing
    resp->set_server_timestamp(server_ts);

    // Vault / audit logging: record the alignment event in a structured way.
    // We use the global vault_log sink with the align_time domain keys.
    std::ostringstream payload;
    payload << "{"
            << "\"peer_id\":\"" << req->peer_id() << "\","
            << "\"session_id\":\"" << session_id << "\","
            << "\"local_root\":\"" << local_anchor_hex << "\","
            << "\"remote_root\":\"" << remote_anchor_hex << "\""
            << "}";

    vault_log(events::ALIGN_CREATED, payload.str());

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
