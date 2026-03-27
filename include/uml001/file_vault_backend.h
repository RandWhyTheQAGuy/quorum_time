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
#pragma once

/**
 * @file file_vault_backend.h
 * @brief Rotation-capable, strong-clock-stamped IVaultBackend implementation.
 *
 * FileVaultBackend writes to a sequence of timestamped log files under
 * a base directory. Each file is named vault_<unix_ts>.log where the
 * timestamp comes from IStrongClock — ensuring tamper-evident ordering.
 */

#include "uml001/vault.h"         
#include "uml001/strong_clock.h"  

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

namespace uml001 {

/**
 * @brief Implementation of IVaultBackend supporting file rotation.
 * * NOTE: Ensure that IVaultBackend in vault.h defines these methods 
 * as 'virtual' or the compiler will throw an 'only virtual member 
 * functions can be marked override' error.
 */
class FileVaultBackend : public IVaultBackend {
public:
    /**
     * @brief Construct a FileVaultBackend.
     *
     * @param base_dir       Root directory for vault files. Created if absent.
     * @param fsync_on_write If true, each append_line() call is fsynced to disk.
     * @param strong_clock   Tamper-evident clock used to timestamp file names.
     */
    FileVaultBackend(
        const std::filesystem::path& base_dir,
        bool fsync_on_write,
        IStrongClock& strong_clock);

    // Virtual destructor is essential for polymorphic cleanup via unique_ptr
    virtual ~FileVaultBackend() override = default;

    /**
     * @brief Append a line to the active vault file.
     * Implements IVaultBackend::append_line.
     */
    void append_line(const std::string& line) override;

    /**
     * @brief Read the last non-empty line from the active vault file.
     * Implements IVaultBackend::read_last_line.
     */
    std::optional<std::string> read_last_line() override;

    /**
     * @brief Archive the active file and open a new timestamped file.
     * Implements IVaultBackend::rotate.
     */
    void rotate() override;

private:
    /**
     * @brief Open a new active file named vault_<strong_clock.now_unix()>.log.
     */
    void open_new_file();

    /**
     * @brief Flush, close, and move the active file to base_dir/archive/.
     */
    void archive_current();

private:
    std::filesystem::path base_dir_;     
    std::filesystem::path active_file_;  

    std::ofstream stream_;               
    bool fsync_on_write_;                

    IStrongClock& strong_clock_;         // Reference to the injected clock
};

} // namespace uml001