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
#include <string>
#include <vector>

#include "uml001/pipeline_event_codec.h"

int main()
{
    using uml001::TimeObservation;

    // Malformed WARP numeric must fail closed without throwing.
    {
        std::vector<TimeObservation> obs;
        double warp = 0.0;
        const bool ok = uml001::pipeline::decode_ntp_sync_payload(
            "WARP not-a-number\nOBS a\tk\t1700\tsig\t1\n", obs, warp);
        assert(!ok);
    }

    // Malformed observation numeric must fail closed without throwing.
    {
        std::vector<TimeObservation> obs;
        double warp = 0.0;
        const bool ok = uml001::pipeline::decode_ntp_sync_payload(
            "WARP 0.0\nOBS a\tk\tnot-int\tsig\t1\n", obs, warp);
        assert(!ok);
    }

    // Malformed shared-state numeric fields must fail closed.
    {
        uint64_t monotonic_version = 0;
        double warp_score = 0.0;
        uint64_t shared_agreed_time = 0;
        int64_t shared_applied_drift = 0;
        uint64_t leader_system_time_at_sync = 0;
        std::string signature_hex;
        std::string leader_id;
        std::string key_id;
        const bool ok = uml001::pipeline::decode_shared_state_payload(
            "nan\n0.1\n1700\n-2\n1700\nsig\nleader\nk1",
            monotonic_version,
            warp_score,
            shared_agreed_time,
            shared_applied_drift,
            leader_system_time_at_sync,
            signature_hex,
            leader_id,
            key_id);
        assert(!ok);
    }

    return 0;
}
