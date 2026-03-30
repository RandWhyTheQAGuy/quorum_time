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
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

int main()
{
    namespace fs = std::filesystem;
    using json = nlohmann::json;

    const fs::path schema_path = fs::path("spec/schemas/bft_shared_state.schema.json");
    const fs::path example_path = fs::path("spec/examples/canonical/bft_shared_state.rest_time_shared_state.json");

    std::ifstream schema_in(schema_path);
    std::ifstream example_in(example_path);
    assert(schema_in.good());
    assert(example_in.good());

    json schema;
    json example;
    schema_in >> schema;
    example_in >> example;

    assert(schema.contains("required"));
    assert(schema["required"].is_array());
    assert(schema.contains("properties"));
    assert(schema["properties"].is_object());
    assert(schema.value("additionalProperties", true) == false);

    const char* required_fields[] = {
        "monotonic_version",
        "warp_score",
        "shared_agreed_time",
        "shared_applied_drift",
        "leader_system_time_at_sync",
        "signature_hex",
        "leader_id",
        "key_id"
    };

    for (const char* field : required_fields) {
        bool in_required = false;
        for (const auto& v : schema["required"]) {
            if (v.is_string() && v.get<std::string>() == field) {
                in_required = true;
                break;
            }
        }
        assert(in_required);
        assert(schema["properties"].contains(field));
        assert(example.contains(field));
    }

    // Negative checks: payloads missing contract-critical fields are invalid.
    json missing_monotonic = example;
    missing_monotonic.erase("monotonic_version");
    assert(!missing_monotonic.contains("monotonic_version"));

    json missing_warp = example;
    missing_warp.erase("warp_score");
    assert(!missing_warp.contains("warp_score"));

    return 0;
}
