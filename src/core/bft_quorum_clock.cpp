/**
 * @file bft_quorum_clock.cpp
 * @brief Byzantine Fault Tolerant Trusted Clock — implementation.
 *
 * This version adds:
 *   - Dynamic, warp-aware drift ceilings and per-round drift steps.
 *   - Signed Shared State adoption from a cluster leader.
 *   - Full audit logging for all trust decisions.
 */

#include "uml001/bft_quorum_clock.h"
#include "uml001/crypto_utils.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace uml001 {

// ============================================================
// Constructor
// ============================================================

BFTQuorumTrustedClock::BFTQuorumTrustedClock(
    BftClockConfig                  config,
    std::unordered_set<std::string> trusted_authorities,
    ColdVault&                      audit_vault
)
    : config_(std::move(config))
    , trusted_authorities_(std::move(trusted_authorities))
    , vault_(audit_vault)
{
    int64_t loaded_drift = vault_.load_last_drift().value_or(0);

    if (std::abs(loaded_drift) > config_.max_total_drift) {
        const int64_t clamped =
            (loaded_drift > 0)
            ?  config_.max_total_drift
            : -config_.max_total_drift;

        const std::string detail =
            "loaded=" + std::to_string(loaded_drift) +
            " clamped_to=" + std::to_string(clamped);

        vault_.log_security_event("bft.cold_start.drift_clamped", detail);

        std::cerr << "[BFT CLOCK] Cold-start drift clamped from "
                  << loaded_drift << " to " << clamped << " seconds.\n";

        current_drift_ = clamped;
    } else {
        current_drift_ = loaded_drift;
    }

    authority_sequences_ = vault_.load_authority_sequences();
}

// ============================================================
// IStrongClock: now_unix()
// ============================================================

uint64_t BFTQuorumTrustedClock::now_unix() const
{
    std::lock_guard<std::mutex> lock(lock_);

    const uint64_t raw_os_time =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );

    const int64_t signed_raw  = static_cast<int64_t>(raw_os_time);
    const int64_t signed_time = signed_raw + current_drift_;

    uint64_t secure_time;
    if (signed_time <= 0) {
        secure_time = 0;
    } else {
        secure_time = static_cast<uint64_t>(signed_time);
    }

    if (secure_time < last_monotonic_read_) {
        secure_time = last_monotonic_read_;
    } else {
        last_monotonic_read_ = secure_time;
    }

    return secure_time;
}

int64_t BFTQuorumTrustedClock::get_current_drift() const
{
    std::lock_guard<std::mutex> lock(lock_);
    return current_drift_;
}

// ============================================================
// Dynamic drift ceilings (warp-aware)
// ============================================================

int64_t BFTQuorumTrustedClock::get_dynamic_drift_ceiling(double warp_score) const
{
    if (warp_score <= 0.0) return config_.max_total_drift;
    if (warp_score >= 1.0) return std::max<int64_t>(1, config_.max_total_drift / 4);

    const double factor  = 1.0 - 0.75 * warp_score;
    const double ceiling = static_cast<double>(config_.max_total_drift) * factor;
    return static_cast<int64_t>(std::max<double>(1.0, std::floor(ceiling)));
}

int64_t BFTQuorumTrustedClock::get_dynamic_drift_step(double warp_score) const
{
    if (warp_score <= 0.0) return config_.max_drift_step;
    if (warp_score >= 1.0) return std::max<int64_t>(1, config_.max_drift_step / 4);

    const double factor = 1.0 - 0.75 * warp_score;
    const double step   = static_cast<double>(config_.max_drift_step) * factor;
    return static_cast<int64_t>(std::max<double>(1.0, std::floor(step)));
}

// ============================================================
// Observation verification
// ============================================================

bool BFTQuorumTrustedClock::verify_observation(
    const TimeObservation& obs) const
{
    if (trusted_authorities_.find(obs.server_hostname) == trusted_authorities_.end()) {
        const std::string detail = "authority=" + obs.server_hostname;
        vault_.log_security_event("bft.verify.unknown_authority", detail);
        std::cerr << "[BFT CLOCK] Rejected unknown authority: "
                  << obs.server_hostname << "\n";
        return false;
    }

    const auto seq_it = authority_sequences_.find(obs.server_hostname);
    if (seq_it != authority_sequences_.end()) {
        if (obs.sequence <= seq_it->second) {
            const std::string detail =
                "authority=" + obs.server_hostname +
                " seq=" + std::to_string(obs.sequence) +
                " last_seen=" + std::to_string(seq_it->second);
            vault_.log_security_event("bft.verify.replay_detected", detail);
            std::cerr << "[BFT CLOCK] Replay detected! Sequence "
                      << obs.sequence << " <= last seen " << seq_it->second
                      << " for " << obs.server_hostname << "\n";
            return false;
        }
    }

    const std::string payload =
        obs.server_hostname + "|" +
        obs.key_id          + "|" +
        std::to_string(obs.unix_seconds) + "|" +
        std::to_string(obs.sequence);

    if (!crypto_verify(payload, obs.signature_hex,
                       obs.server_hostname, obs.key_id))
    {
        const std::string detail =
            "authority=" + obs.server_hostname +
            " key_id=" + obs.key_id;
        vault_.log_security_event("bft.verify.sig_failed", detail);
        std::cerr << "[BFT CLOCK] Signature verification failed for "
                  << obs.server_hostname << " key=" << obs.key_id << "\n";
        return false;
    }

    return true;
}

// ============================================================
// BFT Synchronisation: update_and_sync()
// ============================================================

std::optional<BftSyncResult>
BFTQuorumTrustedClock::update_and_sync(
    const std::vector<TimeObservation>& observations,
    double                              current_warp_score)
{
    uint64_t agreed_time        = 0;
    int64_t  applied_drift_step = 0;
    int64_t  new_total_drift    = 0;
    size_t   n_outliers_ejected = 0;
    size_t   n_rejected         = 0;
    size_t   n_accepted         = 0;
    std::unordered_map<std::string, uint64_t> sequences_snapshot;

    const int64_t dynamic_ceiling = get_dynamic_drift_ceiling(current_warp_score);
    const int64_t dynamic_step    = get_dynamic_drift_step(current_warp_score);

    {
        std::lock_guard<std::mutex> lock(lock_);

        std::vector<uint64_t>        valid_timestamps;
        std::vector<TimeObservation> valid_observations;

        for (const auto& obs : observations) {
            if (verify_observation(obs)) {
                valid_timestamps.push_back(obs.unix_seconds);
                valid_observations.push_back(obs);
            } else {
                ++n_rejected;
            }
        }

        const size_t n_valid = valid_timestamps.size();

        if (n_valid < config_.min_quorum) {
            const std::string detail =
                "valid=" + std::to_string(n_valid) +
                " required=" + std::to_string(config_.min_quorum);
            vault_.log_security_event("bft.sync.quorum_insufficient", detail);
            std::cerr << "[BFT CLOCK] Insufficient quorum. Valid: " << n_valid
                      << " Required: " << config_.min_quorum << "\n";
            return std::nullopt;
        }

        std::sort(valid_timestamps.begin(), valid_timestamps.end());

        const size_t f_tolerance = (n_valid > 0) ? (n_valid - 1) / 3 : 0;

        if (n_valid < (3 * f_tolerance + 1)) {
            const std::string detail =
                "n=" + std::to_string(n_valid) +
                " f=" + std::to_string(f_tolerance);
            vault_.log_security_event("bft.sync.bft_bounds_failed", detail);
            std::cerr << "[BFT CLOCK] Cannot satisfy formal BFT bounds N >= 3F+1.\n";
            return std::nullopt;
        }

        const std::vector<uint64_t> clustered(
            valid_timestamps.begin() + static_cast<std::ptrdiff_t>(f_tolerance),
            valid_timestamps.end()   - static_cast<std::ptrdiff_t>(f_tolerance)
        );

        if (clustered.empty()) {
            vault_.log_security_event("bft.sync.bft_bounds_failed", "clustered_empty_after_trim");
            std::cerr << "[BFT CLOCK] Clustered set empty after PBFT trim.\n";
            return std::nullopt;
        }

        const uint64_t cluster_spread = clustered.back() - clustered.front();

        if (cluster_spread > config_.max_cluster_skew) {
            const std::string detail =
                "spread=" + std::to_string(cluster_spread) +
                " max=" + std::to_string(config_.max_cluster_skew);
            vault_.log_security_event("bft.sync.cluster_skew_exceeded", detail);
            std::cerr << "[BFT CLOCK] Excessive cluster skew: "
                      << cluster_spread << " s > "
                      << config_.max_cluster_skew << " s.\n";
            return std::nullopt;
        }

        const size_t n = clustered.size();
        if (n % 2 == 0) {
            agreed_time = (clustered[n / 2 - 1] + clustered[n / 2]) / 2;
        } else {
            agreed_time = clustered[n / 2];
        }

        const uint64_t raw_os_time =
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );

        const int64_t target_drift =
            static_cast<int64_t>(agreed_time) -
            static_cast<int64_t>(raw_os_time);

        int64_t drift_step = target_drift - current_drift_;

        if (std::abs(drift_step) > dynamic_step) {
            drift_step =
                (drift_step > 0)
                ?  dynamic_step
                : -dynamic_step;
        }

        const int64_t proposed_total = current_drift_ + drift_step;

        if (std::abs(proposed_total) > dynamic_ceiling) {
            const std::string detail =
                "proposed=" + std::to_string(proposed_total) +
                " ceiling=" + std::to_string(dynamic_ceiling) +
                " warp_score=" + std::to_string(current_warp_score);

            vault_.log_security_event("bft.sync.drift_ceiling_exceeded", detail);

            std::cerr << "[BFT CLOCK] Total drift ceiling exceeded: "
                      << proposed_total << " s (ceiling "
                      << dynamic_ceiling << " s).\n";

            if (config_.fail_closed) {
                const std::string abort_detail =
                    "aborting_process " + detail;
                vault_.log_security_event("bft.sync.fail_closed_abort", abort_detail);
                std::cerr << "[BFT CLOCK] fail_closed=true; aborting.\n";
                std::abort();
            }

            return std::nullopt;
        }

        current_drift_ = proposed_total;

        for (const auto& obs : valid_observations) {
            authority_sequences_[obs.server_hostname] = obs.sequence;
        }

        sequences_snapshot   = authority_sequences_;
        applied_drift_step   = drift_step;
        new_total_drift      = current_drift_;
        n_outliers_ejected   = valid_timestamps.size() - clustered.size();
        n_accepted           = clustered.size();

    } // lock_ released

    vault_.log_sync_event(agreed_time, applied_drift_step, new_total_drift);

    vault_.log_security_event(
        "bft.sync.committed",
        "agreed_time=" + std::to_string(agreed_time) +
        " drift_step=" + std::to_string(applied_drift_step) +
        " total_drift=" + std::to_string(new_total_drift) +
        " accepted=" + std::to_string(n_accepted) +
        " outliers=" + std::to_string(n_outliers_ejected) +
        " rejected=" + std::to_string(n_rejected)
    );

    vault_.save_authority_sequences(sequences_snapshot);

    return BftSyncResult{
        .agreed_time      = agreed_time,
        .applied_drift    = applied_drift_step,
        .accepted_sources = n_accepted,
        .outliers_ejected = n_outliers_ejected,
        .rejected_sources = n_rejected
    };
}

// ============================================================
// Shared-State Adoption: apply_shared_state()
// ============================================================

bool BFTQuorumTrustedClock::apply_shared_state(
    uint64_t        shared_agreed_time,
    int64_t         shared_applied_drift,
    uint64_t        leader_system_time_at_sync,
    const std::string& signature_hex,
    const std::string& leader_id,
    const std::string& key_id,
    double          current_warp_score)
{
    const std::string payload =
        leader_id + "|" +
        key_id    + "|" +
        std::to_string(shared_agreed_time) + "|" +
        std::to_string(shared_applied_drift) + "|" +
        std::to_string(leader_system_time_at_sync);

    if (!crypto_verify(payload, signature_hex, leader_id, key_id)) {
        const std::string detail =
            "leader=" + leader_id +
            " key_id=" + key_id;
        vault_.log_security_event("bft.shared_state.sig_failed", detail);
        std::cerr << "[BFT CLOCK] Shared-state signature verification failed "
                  << "for leader=" << leader_id << " key=" << key_id << "\n";
        return false;
    }

    const int64_t dynamic_ceiling = get_dynamic_drift_ceiling(current_warp_score);
    const int64_t dynamic_step    = get_dynamic_drift_step(current_warp_score);

    {
        std::lock_guard<std::mutex> lock(lock_);

        const uint64_t local_os_time =
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );

        if (local_os_time <= leader_system_time_at_sync) {
            const std::string detail =
                "leader_time=" + std::to_string(leader_system_time_at_sync) +
                " local_time=" + std::to_string(local_os_time);
            vault_.log_security_event("bft.shared_state.time_regression", detail);
            std::cerr << "[BFT CLOCK] Shared-state adoption rejected: "
                      << "local OS time <= leader sync time.\n";
            return false;
        }

        const uint64_t delta = local_os_time - leader_system_time_at_sync;
        const uint64_t extrapolated_agreed = shared_agreed_time + delta;

        const int64_t target_drift =
            static_cast<int64_t>(extrapolated_agreed) -
            static_cast<int64_t>(local_os_time);

        int64_t drift_step = target_drift - current_drift_;

        if (std::abs(drift_step) > dynamic_step) {
            drift_step =
                (drift_step > 0)
                ?  dynamic_step
                : -dynamic_step;
        }

        const int64_t proposed_total = current_drift_ + drift_step;

        if (std::abs(proposed_total) > dynamic_ceiling) {
            const std::string detail =
                "proposed=" + std::to_string(proposed_total) +
                " ceiling=" + std::to_string(dynamic_ceiling) +
                " warp_score=" + std::to_string(current_warp_score);

            vault_.log_security_event("bft.shared_state.drift_ceiling_exceeded", detail);

            std::cerr << "[BFT CLOCK] Shared-state drift ceiling exceeded: "
                      << proposed_total << " s (ceiling "
                      << dynamic_ceiling << " s).\n";

            if (config_.fail_closed) {
                const std::string abort_detail =
                    "aborting_process " + detail;
                vault_.log_security_event("bft.shared_state.fail_closed_abort", abort_detail);
                std::cerr << "[BFT CLOCK] fail_closed=true; aborting.\n";
                std::abort();
            }

            return false;
        }

        current_drift_ = proposed_total;

        vault_.log_security_event(
            "bft.shared_state.adopted",
            "leader=" + leader_id +
            " key_id=" + key_id +
            " shared_agreed=" + std::to_string(shared_agreed_time) +
            " extrapolated=" + std::to_string(extrapolated_agreed) +
            " drift_step=" + std::to_string(drift_step) +
            " total_drift=" + std::to_string(current_drift_) +
            " warp_score=" + std::to_string(current_warp_score)
        );
    }

    return true;
}

} // namespace uml001
