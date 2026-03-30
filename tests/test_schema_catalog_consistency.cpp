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
#include <set>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

int main()
{
    namespace fs = std::filesystem;
    using json = nlohmann::json;

    const fs::path repo = fs::path(".");
    const fs::path catalog_path = repo / "spec/schemas/catalog.json";
    std::ifstream in(catalog_path);
    assert(in.good());

    json catalog;
    in >> catalog;
    assert(catalog.contains("schemas"));
    assert(catalog["schemas"].is_array());
    assert(catalog.contains("canonical_examples"));
    assert(catalog["canonical_examples"].is_array());

    std::set<std::string> catalog_schema_paths;
    for (const auto& schema_entry : catalog["schemas"]) {
        assert(schema_entry.is_object());
        assert(schema_entry.contains("path"));
        const std::string rel = schema_entry["path"].get<std::string>();
        const fs::path schema_path = repo / "spec/schemas" / rel;
        assert(fs::exists(schema_path));
        catalog_schema_paths.insert(rel);
    }

    std::set<std::string> catalog_examples;
    for (const auto& example_entry : catalog["canonical_examples"]) {
        assert(example_entry.is_string());
        const std::string rel = example_entry.get<std::string>();
        const fs::path example_path = repo / rel;
        assert(fs::exists(example_path));
        catalog_examples.insert(rel);
    }

    // Reverse completeness: all schema json files (except catalog itself) must be cataloged.
    for (const auto& entry : fs::directory_iterator(repo / "spec/schemas")) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() != ".json") {
            continue;
        }
        const std::string name = entry.path().filename().string();
        if (name == "catalog.json") {
            continue;
        }
        assert(catalog_schema_paths.count(name) == 1);
    }

    // Reverse completeness: all canonical examples must be cataloged.
    for (const auto& entry : fs::directory_iterator(repo / "spec/examples/canonical")) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() != ".json") {
            continue;
        }
        const std::string rel = "spec/examples/canonical/" + entry.path().filename().string();
        assert(catalog_examples.count(rel) == 1);
    }

    return 0;
}
