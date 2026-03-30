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
#include "uml001/ntp_observation_fetcher.h"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>

namespace uml001 {

class ColdVault;

struct BftClockConfig {
    std::uint32_t min_quorum       = 0;
    std::int64_t  max_total_drift  = 3600;
    std::int64_t  max_drift_step   = 60;
    std::int64_t  max_cluster_skew = 10;
    bool          fail_closed      = true;
};

struct BftSyncResult {
    std::uint64_t agreed_time       = 0;
    std::int64_t  drift_step        = 0;
    std::int64_t  applied_drift     = 0;
    std::size_t   clustered_count   = 0;
    std::size_t   discarded_count   = 0;
    std::uint64_t warp_score_bucket = 0;
    std::vector<std::string> accepted_sources;
    std::vector<std::string> rejected_sources;
    std::vector<std::string> outliers_ejected;
};

class BFTQuorumTrustedClock : public IStrongClock {
public:
    // Declare constructor only
    BFTQuorumTrustedClock(
        BftClockConfig config,
        std::unordered_set<std::string> trusted_authorities,
        std::shared_ptr<ColdVault> audit_vault
    );

    std::uint64_t now_unix() const override;
    std::int64_t  get_current_drift() const override;
    std::uint64_t get_current_uncertainty() const;

    std::optional<BftSyncResult> update_and_sync(
        const std::vector<TimeObservation>& observations,
        double current_warp_score = 0.0);

    bool apply_shared_state(std::uint64_t agreed_time, std::int64_t drift,
                            std::uint64_t leader_ts, const std::string& sig,
                            const std::string& leader_id, const std::string& key_id,
                            std::uint64_t version, double warp_score);

    bool verify_observation(const TimeObservation& obs) const;

private:
    std::int64_t get_dynamic_drift_ceiling(double warp_score) const;
    std::int64_t get_dynamic_drift_step(double warp_score) const;
    void latch_fail_closed_unlocked(const std::string& reason, const std::string& detail) const;
    std::uint64_t system_now_unix() const;
    void refresh_runtime_hint(std::uint64_t t) const;

    BftClockConfig config_;
    std::unordered_set<std::string> trusted_authorities_;
    std::shared_ptr<ColdVault> vault_;

    mutable std::mutex lock_;
    std::int64_t  current_drift_{0};
    std::uint64_t last_sync_unix_{0};
    std::uint64_t last_sync_steady_unix_{0};
    mutable std::uint64_t last_monotonic_read_{0};
    std::uint64_t last_shared_version_{0};
    std::unordered_map<std::string, std::uint64_t> authority_sequences_;
    mutable std::atomic<std::uint64_t> runtime_time_hint_{0};
    mutable bool fail_closed_latched_{false};
    mutable bool fail_closed_prequorum_logged_{false};
};

} // namespace uml001