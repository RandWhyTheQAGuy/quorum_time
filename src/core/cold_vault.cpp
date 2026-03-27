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
#include "uml001/vault.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <stdexcept>

namespace uml001 {

// ============================================================
// Constructor
// ============================================================

ColdVault::ColdVault(const Config& cfg,
                     std::shared_ptr<IVaultBackend> backend,
                     IStrongClock& clock,
                     IHashProvider& hash)
    : cfg_(cfg)
    , backend_(std::move(backend)) 
    , clock_(clock)
    , hash_(hash)
    , current_file_size_(0)
    , last_hash_("INITIAL_BOOT")
{
    if (!backend_) {
        throw std::runtime_error("ColdVault: backend shared_ptr is null. Check Python instantiation.");
    }

    ensure_directories();

    drift_file_ = cfg_.base_directory / "drift.state";
    seq_file_   = cfg_.base_directory / "authority_sequences.state";

    current_file_start_time_ = clock_.now_unix();

    // Restore previous hash from backend if available
    try {
        auto last_line = backend_->read_last_line();
        if (last_line && !last_line->empty()) {
            auto pos = last_line->find("hash=");
            if (pos != std::string::npos) {
                last_hash_ = last_line->substr(pos + 5);
            }
        }
    } catch (...) {
        // If backend read fails, start fresh
    }
}

// ============================================================
// Directory setup
// ============================================================

void ColdVault::ensure_directories()
{
    if (!cfg_.base_directory.empty()) {
        std::filesystem::create_directories(cfg_.base_directory);
    }
}

// ============================================================
// Rotation (Safety Guarded)
// ============================================================

void ColdVault::maybe_rotate()
{
    if (!backend_) return; 

    uint64_t now = clock_.now_unix();

    if (current_file_start_time_ == 0) current_file_start_time_ = now;

    if (current_file_size_ >= cfg_.max_file_size_bytes ||
        (now - current_file_start_time_) >= cfg_.max_file_age_seconds)
    {
        backend_->rotate();
        current_file_start_time_ = now;
        current_file_size_ = 0;
        last_hash_ = "ROTATE_BOUNDARY";
    }
}

// ============================================================
// Audit Logging
// ============================================================

void ColdVault::log_security_event(const std::string& key, const std::string& detail)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = clock_.now_unix();
    std::ostringstream oss;
    oss << "ts=" << ts << " type=security key=" << key << " detail=" << detail 
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash = hash_.sha256(content);
    last_hash_ = hash;

    std::string full_line = content + " hash=" + hash;
    backend_->append_line(full_line);
    current_file_size_ += full_line.size() + 1;
}

void ColdVault::log_sync_event(uint64_t agreed_time, int64_t drift_step, int64_t total_drift)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = clock_.now_unix();
    std::ostringstream oss;
    oss << "ts=" << ts << " type=sync agreed=" << agreed_time 
        << " drift_step=" << drift_step << " total_drift=" << total_drift 
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash = hash_.sha256(content);
    last_hash_ = hash;

    std::string full_line = content + " hash=" + hash;
    backend_->append_line(full_line);
    current_file_size_ += full_line.size() + 1;
}

void ColdVault::log_key_rotation_event(uint64_t new_version, uint64_t unix_time)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    std::ostringstream oss;
    oss << "ts=" << unix_time << " type=key_rotation version=" << new_version 
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash = hash_.sha256(content);
    last_hash_ = hash;

    std::string full_line = content + " hash=" + hash;
    backend_->append_line(full_line);
    current_file_size_ += full_line.size() + 1;
}

// ============================================================
// Drift Persistence
// ============================================================

std::optional<int64_t> ColdVault::load_last_drift()
{
    std::ifstream in(drift_file_);
    if (!in) return std::nullopt;

    int64_t v = 0;
    if (!(in >> v)) return std::nullopt;
    return v;
}

void ColdVault::save_last_drift(int64_t drift)
{
    std::ofstream out(drift_file_, std::ios::trunc);
    if (out.is_open()) {
        out << drift;
    }
}

// ============================================================
// Authority Sequence Persistence
// ============================================================

std::unordered_map<std::string, uint64_t>
ColdVault::load_authority_sequences()
{
    std::unordered_map<std::string, uint64_t> out;

    std::ifstream in(seq_file_);
    if (!in) return out;

    std::string line;
    while (std::getline(in, line)) {
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        try {
            uint64_t val = std::stoull(line.substr(pos + 1));
            out[key] = val;
        } catch (...) {
            continue; 
        }
    }

    return out;
}

void ColdVault::save_authority_sequences(
    const std::unordered_map<std::string, uint64_t>& seqs)
{
    std::ofstream out(seq_file_, std::ios::trunc);
    if (!out.is_open()) return;
    
    for (const auto& kv : seqs) {
        out << kv.first << "=" << kv.second << "\n";
    }
}

} // namespace uml001