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
    shared_state_file_ = cfg_.base_directory / "shared_state.state";

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

    uint64_t now = current_time_unix();

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

void ColdVault::set_time_source(std::function<uint64_t()> fn)
{
    std::lock_guard<std::mutex> lock(mutex_);
    time_source_ = std::move(fn);
}

uint64_t ColdVault::current_time_unix() const
{
    if (time_source_) {
        return time_source_();
    }
    return clock_.now_unix();
}

// ============================================================
// Audit Logging
// ============================================================

void ColdVault::log_security_event(const std::string& key, const std::string& detail)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = current_time_unix();
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

    uint64_t ts = current_time_unix();
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

std::string ColdVault::chain_head_hash() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return last_hash_;
}

void ColdVault::log_pipeline_event(const std::string& event_id,
                                   const std::string& serialized_signed_state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = current_time_unix();
    std::ostringstream oss;
    oss << "ts=" << ts << " type=pipeline event_id=" << event_id
        << " payload_len=" << serialized_signed_state.size()
        << " payload_sha256=" << hash_.sha256(serialized_signed_state)
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

    std::optional<int64_t> last;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const std::string prefix = "drift=";
        if (line.rfind(prefix, 0) != 0) continue;
        try {
            last = std::stoll(line.substr(prefix.size()));
        } catch (...) {
            continue;
        }
    }
    return last;
}

void ColdVault::save_last_drift(int64_t drift)
{
    std::ofstream out(drift_file_, std::ios::app);
    if (out.is_open()) {
        out << "drift=" << drift << "\n";
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
        const std::string prefix = "seq ";
        if (line.rfind(prefix, 0) != 0) continue;

        auto pos = line.find('=', prefix.size());
        if (pos == std::string::npos) continue;

        std::string key = line.substr(prefix.size(), pos - prefix.size());
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
    std::ofstream out(seq_file_, std::ios::app);
    if (!out.is_open()) return;

    out << "snapshot_ts=" << current_time_unix() << "\n";
    for (const auto& kv : seqs) {
        out << "seq " << kv.first << "=" << kv.second << "\n";
    }
}

void ColdVault::save_shared_state_snapshot(const SharedStateSnapshot& snapshot)
{
    std::ofstream out(shared_state_file_, std::ios::app);
    if (!out.is_open()) return;

    out << "shared agreed=" << snapshot.agreed_time
        << " drift=" << snapshot.applied_drift
        << " version=" << snapshot.version << "\n";
}

std::optional<ColdVault::SharedStateSnapshot> ColdVault::load_shared_state_snapshot()
{
    std::ifstream in(shared_state_file_);
    if (!in) return std::nullopt;

    std::optional<SharedStateSnapshot> last;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("shared ", 0) != 0) continue;

        SharedStateSnapshot snap;
        bool ok = false;
        try {
            const auto a = line.find("agreed=");
            const auto d = line.find(" drift=");
            const auto v = line.find(" version=");
            if (a != std::string::npos && d != std::string::npos && v != std::string::npos) {
                const auto agreed_s = line.substr(a + 7, d - (a + 7));
                const auto drift_s = line.substr(d + 7, v - (d + 7));
                const auto version_s = line.substr(v + 9);
                snap.agreed_time = static_cast<uint64_t>(std::stoull(agreed_s));
                snap.applied_drift = static_cast<int64_t>(std::stoll(drift_s));
                snap.version = static_cast<uint64_t>(std::stoull(version_s));
                ok = true;
            }
        } catch (...) {
            ok = false;
        }
        if (ok) {
            last = snap;
        }
    }
    return last;
}

} // namespace uml001