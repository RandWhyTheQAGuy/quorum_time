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
#include "uml001/simple_file_vault_backend.h"

#include <fstream>
#include <stdexcept>
#include <filesystem>

namespace uml001 {

SimpleFileVaultBackend::SimpleFileVaultBackend(const std::filesystem::path& input_path)
{
    // 🔥 FIX: Treat input as directory if it doesn't look like a file
    if (input_path.has_extension()) {
        // Explicit file path
        path_ = input_path;
        std::filesystem::create_directories(path_.parent_path());
    } else {
        // Directory path (this is what tests use)
        std::filesystem::create_directories(input_path);
        path_ = input_path / "vault.log";
    }

    // 🔥 Ensure file exists
    std::ofstream out(path_, std::ios::app);
    if (!out.is_open()) {
        throw std::runtime_error(
            "SimpleFileVaultBackend: Initial file creation/access failed: " + path_.string()
        );
    }
}

void SimpleFileVaultBackend::append_line(const std::string& line)
{
    std::ofstream out(path_, std::ios::app | std::ios::binary);
    if (!out.is_open()) {
        throw std::runtime_error("SimpleFileVaultBackend: Failed to open file for append");
    }

    out << line << "\n";

    if (!out.good()) {
        throw std::runtime_error("SimpleFileVaultBackend: Write failed");
    }
}

std::optional<std::string> SimpleFileVaultBackend::read_last_line()
{
    if (!std::filesystem::exists(path_)) {
        return std::nullopt;
    }

    std::ifstream in(path_, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }

    std::string line;
    std::string last;

    while (std::getline(in, line)) {
        if (!line.empty()) {
            last = line;
        }
    }

    if (last.empty()) return std::nullopt;
    return last;
}

void SimpleFileVaultBackend::rotate()
{
    // No-op for simple backend
}

} // namespace uml001