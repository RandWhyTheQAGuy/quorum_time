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

#include "uml001/strong_clock.h"
#include "uml001/hash_provider.h"
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace uml001 {

/**
 * @brief Interface for vault storage backends.
 */
class IVaultBackend {
public:
    virtual ~IVaultBackend() = default;
    virtual void append_line(const std::string& line) = 0;
    virtual std::optional<std::string> read_last_line() = 0;
    virtual void rotate() = 0;
};

/**
 * @brief ColdVault maintains a tamper-evident audit log for drift and key rotations.
 */
class ColdVault {
public:
    struct SharedStateSnapshot {
        std::uint64_t agreed_time = 0;
        std::int64_t applied_drift = 0;
        std::uint64_t version = 0;
    };

    // --- Config struct ---
    struct Config {
        std::filesystem::path base_directory;
        uint64_t max_file_size_bytes  = 10 * 1024 * 1024;
        uint64_t max_file_age_seconds = 86400;
    };

    // Correctly qualified getter
    const ColdVault::Config& config() const { return cfg_; }

    // Constructor now accepts shared_ptr for Pybind11 compatibility
    ColdVault(const Config& cfg, 
              std::shared_ptr<IVaultBackend> backend, 
              IStrongClock& clock, 
              IHashProvider& hasher);

    // Drift persistence
    void save_last_drift(std::int64_t drift);
    std::optional<std::int64_t> load_last_drift();

    // Authority sequences
    void save_authority_sequences(const std::unordered_map<std::string, std::uint64_t>& seqs);
    std::unordered_map<std::string, std::uint64_t> load_authority_sequences();
    void save_shared_state_snapshot(const SharedStateSnapshot& snapshot);
    std::optional<SharedStateSnapshot> load_shared_state_snapshot();

    // Logging
    void log_sync_event(std::uint64_t agreed_time, std::int64_t drift_step, std::int64_t total_drift);
    void log_security_event(const std::string& event_type, const std::string& details);
    void log_key_rotation_event(uint64_t key_version, uint64_t unix_time);

    /// Current hash-chain head (after last append). Used by VaultStage for deterministic binding.
    std::string chain_head_hash() const;

    /// Append-only pipeline event record (serialized SignedState envelope).
    void log_pipeline_event(const std::string& event_id, const std::string& serialized_signed_state);

    /// Optional runtime time source override (used for BFT-time-consistent audit timestamps).
    void set_time_source(std::function<uint64_t()> fn);

private:
    void ensure_directories();
    void maybe_rotate();
    uint64_t current_time_unix() const;

    ColdVault::Config               cfg_;       // Qualified type
    std::shared_ptr<IVaultBackend>  backend_;   // Matches constructor
    IStrongClock&                   clock_;
    IHashProvider&                  hash_;

    mutable std::mutex              mutex_;
    std::function<uint64_t()>       time_source_;
    std::filesystem::path           drift_file_;
    std::filesystem::path           seq_file_;
    std::filesystem::path           shared_state_file_;
    std::string                     last_hash_;
    uint64_t                        current_file_start_time_ = 0;
    uint64_t                        current_file_size_       = 0;
};

} // namespace uml001