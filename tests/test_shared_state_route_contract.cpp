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
#include <cassert>
#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"

int main()
{
    using json = nlohmann::json;

    // Mirrors the required REST /time/shared-state request contract.
    json body = {
        {"monotonic_version", static_cast<std::uint64_t>(7)},
        {"warp_score", 0.125},
        {"shared_agreed_time", static_cast<std::uint64_t>(1700000100)},
        {"shared_applied_drift", static_cast<std::int64_t>(-2)},
        {"leader_system_time_at_sync", static_cast<std::uint64_t>(1700000100)},
        {"signature_hex", "abcdef"},
        {"leader_id", "leader-A"},
        {"key_id", "k1"}
    };

    const char* req_fields[] = {
        "monotonic_version",
        "warp_score",
        "shared_agreed_time",
        "shared_applied_drift",
        "leader_system_time_at_sync",
        "signature_hex",
        "leader_id",
        "key_id"
    };
    for (const char* f : req_fields) {
        assert(body.contains(f));
    }

    std::string payload;
    uml001::pipeline::encode_shared_state_payload(
        body["monotonic_version"].get<std::uint64_t>(),
        body["warp_score"].get<double>(),
        body["shared_agreed_time"].get<std::uint64_t>(),
        body["shared_applied_drift"].get<std::int64_t>(),
        body["leader_system_time_at_sync"].get<std::uint64_t>(),
        body["signature_hex"].get<std::string>(),
        body["leader_id"].get<std::string>(),
        body["key_id"].get<std::string>(),
        &payload);

    std::uint64_t monotonic_version = 0;
    double warp_score = 0.0;
    std::uint64_t shared_agreed_time = 0;
    std::int64_t shared_applied_drift = 0;
    std::uint64_t leader_system_time_at_sync = 0;
    std::string signature_hex;
    std::string leader_id;
    std::string key_id;

    const bool ok = uml001::pipeline::decode_shared_state_payload(
        payload,
        monotonic_version,
        warp_score,
        shared_agreed_time,
        shared_applied_drift,
        leader_system_time_at_sync,
        signature_hex,
        leader_id,
        key_id);
    assert(ok);
    assert(!uml001::pipeline::decode_shared_state_payload(
        payload + "\nsmuggled_field",
        monotonic_version,
        warp_score,
        shared_agreed_time,
        shared_applied_drift,
        leader_system_time_at_sync,
        signature_hex,
        leader_id,
        key_id));

    assert(monotonic_version == body["monotonic_version"].get<std::uint64_t>());
    assert(warp_score == body["warp_score"].get<double>());
    assert(shared_agreed_time == body["shared_agreed_time"].get<std::uint64_t>());
    assert(shared_applied_drift == body["shared_applied_drift"].get<std::int64_t>());
    assert(leader_system_time_at_sync == body["leader_system_time_at_sync"].get<std::uint64_t>());
    assert(signature_hex == body["signature_hex"].get<std::string>());
    assert(leader_id == body["leader_id"].get<std::string>());
    assert(key_id == body["key_id"].get<std::string>());

    // Route contract emits external REST event ID; policy stage converts to internal.
    assert(std::string(uml001::pipeline::REST_TIME_SHARED_STATE) ==
           "uml001.rest.time.shared_state");
    assert(std::string(uml001::pipeline::INTERNAL_SHARED_STATE_APPLY) ==
           "uml001.internal.shared_state.apply");
    return 0;
}
