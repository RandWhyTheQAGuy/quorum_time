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

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace uml001 {

struct NtpServerEntry {
    std::string   hostname;
    std::uint32_t timeout_ms;
    std::uint32_t max_delay_ms; 
};

struct NtpObservation {
    std::string   server_hostname;
    std::uint64_t unix_seconds;
    std::uint64_t rtt_ms;
    std::uint8_t  stratum;
    bool          is_outlier;
};

struct TimeObservation {
    std::string   server_hostname;
    std::string   key_id;
    std::uint64_t unix_seconds;
    std::string   signature_hex;
    std::uint64_t sequence;
};

struct TimestampAttestationToken {
    std::uint64_t unix_time;
    std::uint64_t median_rtt_ms;
    std::uint64_t drift_ppm;
    std::vector<std::string> servers;
    std::string   quorum_hash_hex;
    std::string   signature_hex;
};

class NtpObservationFetcher {
public:
    NtpObservationFetcher(const std::string& hmac_key,
                          const std::string& key_id,
                          const std::vector<NtpServerEntry>& servers,
                          std::size_t quorum_size,
                          std::uint32_t timeout_ms,
                          std::uint32_t max_delay_ms);
    
    virtual ~NtpObservationFetcher() = default;

    void set_hmac_key(const std::string& new_hmac_key); 
    std::vector<TimeObservation> fetch();
    std::size_t get_active_authority_count() const;
    
    // State management
    std::string save_sequence_state() const;
    void load_sequence_state(const std::string& state_data); // Added for bindings

private:
    std::optional<NtpObservation> query_server(const NtpServerEntry& server) const;
    TimeObservation sign_observation(const NtpObservation& raw);
    bool is_byzantine_outlier(std::uint64_t value, const std::vector<std::uint64_t>& values) const;
    std::uint64_t median(std::vector<std::uint64_t> values) const;
    std::uint64_t estimate_drift(std::uint64_t new_time);
    std::optional<TimestampAttestationToken> build_quorum_token(const std::vector<NtpObservation>& obs);

private:
    std::string hmac_key_;
    std::string key_id_;
    std::vector<NtpServerEntry> servers_;
    std::size_t   quorum_size_;
    std::uint32_t timeout_ms_;
    std::uint32_t max_delay_ms_;
    std::uint64_t outlier_threshold_s_;

    mutable std::mutex seq_mutex_;
    std::unordered_map<std::string, std::uint64_t> sequences_;

    mutable std::mutex drift_mutex_;
    std::uint64_t last_reference_time_{0};
    std::uint64_t last_local_time_{0};
};

} // namespace uml001