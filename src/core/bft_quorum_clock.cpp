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
#include "uml001/bft_quorum_clock.h"
#include "uml001/vault.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/crypto_utils.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace uml001 {

void BFTQuorumTrustedClock::latch_fail_closed_unlocked(
    const std::string& reason,
    const std::string& detail) const
{
    if (!config_.fail_closed || fail_closed_latched_) {
        return;
    }
    fail_closed_latched_ = true;
    if (vault_) {
        vault_->log_security_event(
            "bft.fail_closed.latched",
            "reason=" + reason + " detail=" + detail);
    }
}

uint64_t BFTQuorumTrustedClock::system_now_unix() const {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

void BFTQuorumTrustedClock::refresh_runtime_hint(uint64_t t) const {
    runtime_time_hint_.store(t, std::memory_order_relaxed);
}

// Constructor
BFTQuorumTrustedClock::BFTQuorumTrustedClock(
    BftClockConfig                  config,
    std::unordered_set<std::string> trusted_authorities,
    std::shared_ptr<ColdVault>      audit_vault
)
    : config_(std::move(config))
    , trusted_authorities_(std::move(trusted_authorities))
    , vault_(std::move(audit_vault))
{
    std::string resume_status = "ignored";
    std::string resume_detail = "no_snapshot";
    int64_t loaded_drift = vault_->load_last_drift().value_or(0);

    if (std::abs(loaded_drift) > config_.max_total_drift) {
        const int64_t clamped = (loaded_drift > 0)
            ? config_.max_total_drift
            : -config_.max_total_drift;
        vault_->log_security_event("bft.cold_start.drift_clamped",
                                   std::to_string(clamped));
        current_drift_ = clamped;
    } else {
        current_drift_ = loaded_drift;
    }

    authority_sequences_ = vault_->load_authority_sequences();

    if (auto shared = vault_->load_shared_state_snapshot(); shared.has_value()) {
        if (shared->agreed_time > 0 && shared->version > 0) {
            std::int64_t resumed_drift = shared->applied_drift;
            if (std::abs(resumed_drift) > config_.max_total_drift) {
                resumed_drift = (resumed_drift > 0)
                    ? config_.max_total_drift
                    : -config_.max_total_drift;
                vault_->log_security_event(
                    "bft.resume.shared_state.drift_clamped",
                    std::to_string(resumed_drift));
                resume_status = "clamped";
                resume_detail = "drift_out_of_bounds";
            } else {
                resume_status = "applied";
                resume_detail = "ok";
            }
            current_drift_ = resumed_drift;
            last_sync_unix_ = shared->agreed_time;
            last_shared_version_ = shared->version;
        } else {
            vault_->log_security_event(
                "bft.resume.shared_state.invalid",
                "ignored malformed shared snapshot");
            resume_status = "ignored";
            resume_detail = "malformed_snapshot";
        }
    }

    const uint64_t cold_start = system_now_unix();
    int64_t signed_time = static_cast<int64_t>(cold_start) + current_drift_;
    const uint64_t hinted = (signed_time <= 0) ? 0 : static_cast<uint64_t>(signed_time);
    refresh_runtime_hint(hinted);
    if (last_sync_unix_ > 0) {
        last_sync_steady_unix_ = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );
        refresh_runtime_hint(last_sync_unix_);
    }

    if (vault_) {
        vault_->set_time_source([this]() {
            const uint64_t t = runtime_time_hint_.load(std::memory_order_relaxed);
            return t == 0 ? this->system_now_unix() : t;
        });
        vault_->log_security_event(
            "bft.resume.startup",
            "status=" + resume_status + " detail=" + resume_detail);
    }
}

uint64_t BFTQuorumTrustedClock::now_unix() const {
    std::lock_guard<std::mutex> lock(lock_);
    if (config_.fail_closed) {
        if (fail_closed_latched_) {
            return 0;
        }
        if (last_sync_unix_ == 0) {
            if (!fail_closed_prequorum_logged_ && vault_) {
                vault_->log_security_event(
                    "bft.time.blocked",
                    "reason=pre_quorum_fail_closed");
                fail_closed_prequorum_logged_ = true;
            }
            return 0;
        }
    }

    uint64_t secure_time = 0;
    if (last_sync_unix_ == 0) {
        const uint64_t raw_os_time = system_now_unix();
        int64_t signed_time = static_cast<int64_t>(raw_os_time) + current_drift_;
        secure_time = (signed_time <= 0) ? 0 : static_cast<uint64_t>(signed_time);
    } else {
        const uint64_t steady_now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );
        const uint64_t elapsed = (steady_now > last_sync_steady_unix_)
            ? (steady_now - last_sync_steady_unix_)
            : 0;
        secure_time = last_sync_unix_ + elapsed;
    }

    if (secure_time < last_monotonic_read_) {
        secure_time = last_monotonic_read_;
    } else {
        last_monotonic_read_ = secure_time;
    }
    refresh_runtime_hint(secure_time);
    return secure_time;
}

int64_t BFTQuorumTrustedClock::get_current_drift() const {
    std::lock_guard<std::mutex> lock(lock_);
    return current_drift_;
}

uint64_t BFTQuorumTrustedClock::get_current_uncertainty() const {
    std::lock_guard<std::mutex> lock(lock_);
    if (last_sync_unix_ == 0) return 0xFFFFFFFF;

    const uint64_t steady_now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
    const uint64_t elapsed = (steady_now > last_sync_steady_unix_)
        ? (steady_now - last_sync_steady_unix_)
        : 0;
    const uint64_t now = last_sync_unix_ + elapsed;

    if (now <= last_sync_unix_) return 0;
    return now - last_sync_unix_;
}

int64_t BFTQuorumTrustedClock::get_dynamic_drift_ceiling(double warp_score) const {
    if (warp_score <= 0.0) return config_.max_total_drift;
    if (warp_score >= 1.0) return std::max<int64_t>(1, config_.max_total_drift / 4);
    const double factor = 1.0 - 0.75 * warp_score;
    return static_cast<int64_t>(std::max<double>(1.0, std::floor(config_.max_total_drift * factor)));
}

int64_t BFTQuorumTrustedClock::get_dynamic_drift_step(double warp_score) const {
    if (warp_score <= 0.0) return config_.max_drift_step;
    if (warp_score >= 1.0) return std::max<int64_t>(1, config_.max_drift_step / 4);
    const double factor = 1.0 - 0.75 * warp_score;
    return static_cast<int64_t>(std::max<double>(1.0, std::floor(config_.max_drift_step * factor)));
}

bool BFTQuorumTrustedClock::verify_observation(const TimeObservation& obs) const {
    if (trusted_authorities_.find(obs.server_hostname) == trusted_authorities_.end()) {
        vault_->log_security_event(
            "bft.observation.reject",
            "reason=untrusted_authority authority=" + obs.server_hostname);
        return false;
    }

    auto it = authority_sequences_.find(obs.server_hostname);
    if (it != authority_sequences_.end() && obs.sequence <= it->second) {
        vault_->log_security_event(
            "bft.observation.reject",
            "reason=stale_sequence authority=" + obs.server_hostname +
            " seq=" + std::to_string(obs.sequence) +
            " last=" + std::to_string(it->second));
        return false;
    }

    const std::string payload =
        obs.server_hostname + "|" + obs.key_id + "|" +
        std::to_string(obs.unix_seconds) + "|" +
        std::to_string(obs.sequence);

    bool ok = false;
    try {
        ok = crypto_verify(payload, obs.signature_hex, obs.server_hostname, obs.key_id);
    } catch (...) {
        ok = false;
    }
    if (!ok) {
        vault_->log_security_event(
            "bft.observation.reject",
            "reason=signature_invalid authority=" + obs.server_hostname +
            " key_id=" + obs.key_id);
    }
    return ok;
}

std::optional<BftSyncResult> BFTQuorumTrustedClock::update_and_sync(
    const std::vector<TimeObservation>& observations,
    double current_warp_score
) {
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (config_.fail_closed && fail_closed_latched_) {
            vault_->log_security_event("bft.sync.reject", "reason=fail_closed_latched");
            return std::nullopt;
        }
    }

    std::vector<uint64_t> valid_ts;
    std::vector<TimeObservation> valid_obs;
    std::vector<std::string> accepted_sources;
    std::vector<std::string> rejected_sources;

    for (const auto& obs : observations) {
        if (verify_observation(obs)) {
            valid_ts.push_back(obs.unix_seconds);
            valid_obs.push_back(obs);
            accepted_sources.push_back(obs.server_hostname);
        } else {
            rejected_sources.push_back(obs.server_hostname);
        }
    }

    if (valid_ts.size() < config_.min_quorum) {
        vault_->log_security_event(
            "bft.sync.reject",
            "reason=insufficient_quorum valid=" + std::to_string(valid_ts.size()) +
            " required=" + std::to_string(config_.min_quorum));
        std::lock_guard<std::mutex> lock(lock_);
        latch_fail_closed_unlocked("sync_insufficient_quorum",
                                   "valid=" + std::to_string(valid_ts.size()));
        return std::nullopt;
    }

    std::sort(valid_ts.begin(), valid_ts.end());
    const size_t f = (valid_ts.size() - 1) / 3;
    const std::vector<uint64_t> clustered(valid_ts.begin() + f, valid_ts.end() - f);
    if (clustered.empty()) {
        vault_->log_security_event("bft.sync.reject", "reason=empty_cluster_after_trim");
        std::lock_guard<std::mutex> lock(lock_);
        latch_fail_closed_unlocked("sync_empty_cluster", "");
        return std::nullopt;
    }

    std::vector<std::string> outliers_ejected;
    const uint64_t cluster_min = clustered.front();
    const uint64_t cluster_max = clustered.back();
    for (const auto& o : valid_obs) {
        if (o.unix_seconds < cluster_min || o.unix_seconds > cluster_max)
            outliers_ejected.push_back(o.server_hostname);
    }

    const uint64_t agreed_time = clustered[clustered.size() / 2];
    if ((cluster_max - cluster_min) > static_cast<uint64_t>(config_.max_cluster_skew)) {
        vault_->log_security_event(
            "bft.sync.reject",
            "reason=cluster_skew_exceeded skew=" + std::to_string(cluster_max - cluster_min) +
            " max=" + std::to_string(config_.max_cluster_skew));
        std::lock_guard<std::mutex> lock(lock_);
        latch_fail_closed_unlocked("sync_cluster_skew_exceeded", "");
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(lock_);
    const uint64_t raw_os = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    int64_t target_drift = static_cast<int64_t>(agreed_time) - static_cast<int64_t>(raw_os);
    int64_t drift_step = target_drift - current_drift_;
    const int64_t max_step = get_dynamic_drift_step(current_warp_score);
    if (std::abs(drift_step) > max_step) drift_step = (drift_step > 0) ? max_step : -max_step;

    current_drift_ += drift_step;
    const int64_t max_total = get_dynamic_drift_ceiling(current_warp_score);
    if (std::abs(current_drift_) > max_total) {
        vault_->log_security_event(
            "bft.sync.reject",
            "reason=drift_ceiling_exceeded applied=" + std::to_string(current_drift_) +
            " ceiling=" + std::to_string(max_total));
        latch_fail_closed_unlocked("sync_drift_ceiling_exceeded", "");
        return std::nullopt;
    }
    last_sync_unix_ = agreed_time;
    last_shared_version_ += 1;
    last_sync_steady_unix_ = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
    refresh_runtime_hint(agreed_time);
    vault_->save_last_drift(current_drift_);
    vault_->save_shared_state_snapshot(
        ColdVault::SharedStateSnapshot{agreed_time, current_drift_, last_shared_version_});

    for (const auto& o : valid_obs) {
        authority_sequences_[o.server_hostname] = o.sequence;
    }
    vault_->save_authority_sequences(authority_sequences_);
    vault_->log_sync_event(agreed_time, drift_step, current_drift_);

    BftSyncResult result;
    result.agreed_time       = agreed_time;
    result.drift_step        = drift_step;
    result.applied_drift     = current_drift_;
    result.clustered_count   = clustered.size();
    result.discarded_count   = valid_ts.size() - clustered.size();
    result.warp_score_bucket = 0;
    result.accepted_sources  = std::move(accepted_sources);
    result.rejected_sources  = std::move(rejected_sources);
    result.outliers_ejected  = std::move(outliers_ejected);
    return result;
}

bool BFTQuorumTrustedClock::apply_shared_state(
    uint64_t           agreed_time,
    int64_t            drift,
    uint64_t           leader_ts,
    const std::string& sig,
    const std::string& leader_id,
    const std::string& key_id,
    uint64_t           version,
    double             warp_score
) {
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (config_.fail_closed && fail_closed_latched_) {
            vault_->log_security_event("bft.shared_state.reject", "reason=fail_closed_latched");
            return false;
        }
    }

    const std::string payload =
        leader_id + "|" + key_id + "|" +
        std::to_string(agreed_time) + "|" +
        std::to_string(drift) + "|" +
        std::to_string(leader_ts) + "|" +
        std::to_string(version) + "|" +
        ([&warp_score]() {
            std::ostringstream oss;
            oss << std::setprecision(17) << warp_score;
            return oss.str();
        })();

    bool signature_ok = false;
    try {
        signature_ok = crypto_verify(payload, sig, leader_id, key_id);
    } catch (...) {
        signature_ok = false;
    }
    if (!signature_ok) {
        vault_->log_security_event(
            "bft.shared_state.reject",
            "reason=signature_invalid leader=" + leader_id + " key_id=" + key_id);
        std::lock_guard<std::mutex> lock(lock_);
        latch_fail_closed_unlocked("shared_state_signature_invalid", "leader=" + leader_id);
        return false;
    }

    std::lock_guard<std::mutex> lock(lock_);
    if (version <= last_shared_version_) {
        vault_->log_security_event(
            "bft.shared_state.reject",
            "reason=stale_version version=" + std::to_string(version) +
            " last=" + std::to_string(last_shared_version_));
        latch_fail_closed_unlocked("shared_state_stale_version", "version=" + std::to_string(version));
        return false;
    }

    const uint64_t local_os = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );

    if (local_os < leader_ts) {
        vault_->log_security_event(
            "bft.shared_state.reject",
            "reason=leader_ts_in_future leader_ts=" + std::to_string(leader_ts) +
            " local=" + std::to_string(local_os));
        latch_fail_closed_unlocked("shared_state_future_leader_ts", "");
        return false;
    }

    current_drift_ =
        static_cast<int64_t>(agreed_time + (local_os - leader_ts)) -
        static_cast<int64_t>(local_os);
    const int64_t max_total = get_dynamic_drift_ceiling(warp_score);
    if (std::abs(current_drift_) > max_total) {
        vault_->log_security_event(
            "bft.shared_state.reject",
            "reason=drift_ceiling_exceeded applied=" + std::to_string(current_drift_) +
            " ceiling=" + std::to_string(max_total));
        latch_fail_closed_unlocked("shared_state_drift_ceiling_exceeded", "");
        return false;
    }

    last_shared_version_ = version;
    last_sync_unix_ = agreed_time;
    last_sync_steady_unix_ = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );
    refresh_runtime_hint(agreed_time);
    vault_->save_last_drift(current_drift_);
    vault_->save_shared_state_snapshot(
        ColdVault::SharedStateSnapshot{agreed_time, current_drift_, last_shared_version_});
    return true;
}

} // namespace uml001