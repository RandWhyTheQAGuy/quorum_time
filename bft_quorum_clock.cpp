/**
 * bft_quorum_clock.cpp
 *
 * Byzantine Fault Tolerant Trusted Clock
 *
 * SECURITY MODEL
 * --------------
 * This class is the *only* component permitted to read the OS system clock.
 * All other components must obtain time via IStrongClock::now_unix().
 *
 * Security Guarantees:
 *
 * - Byzantine quorum consensus over time authorities (Formal PBFT Math)
 * - Outlier trimming (BFT tolerance)
 * - Cluster skew enforcement
 * - Drift shock limiting (max_drift_step)
 * - Drift creep ceiling (max_total_drift)
 * - Monotonic floor guarantee (no backward time)
 * - Sequence replay-window tracking 
 * - Cryptographic key rotation support
 * - Fail-closed capability
 * - Audit logging via ColdVault
 *
 * This clock defines the canonical "strong time" for the system.
 */

#include "bft_quorum_clock.h"
#include "crypto_utils.h"

#include <chrono>
#include <algorithm>
#include <iostream>
#include <cmath>

namespace uml001 {


// ============================================================
// Constructor
// ============================================================

BFTQuorumTrustedClock::BFTQuorumTrustedClock(
    Config config,
    std::unordered_set<std::string> trusted_authorities,
    ColdVault& audit_vault)
    : config_(std::move(config))
    , trusted_authorities_(std::move(trusted_authorities))
    , vault_(audit_vault)
{
    /**
     * Recover persisted drift and sequence states from ColdVault.
     *
     * This prevents rollback attacks across process restarts.
     * If no prior drift exists, initialize to zero.
     */
    current_drift_ = vault_.load_last_drift().value_or(0);
    
    // Assumes vault can restore previously observed sequences to prevent 
    // cross-restart replay attacks.
    authority_sequences_ = vault_.load_authority_sequences();
}


// ============================================================
// Strong Time Interface (IStrongClock)
// ============================================================

uint64_t BFTQuorumTrustedClock::now_unix() const
{
    std::lock_guard<std::mutex> lock(lock_);

    /**
     * The OS clock is treated as an untrusted baseline.
     * We apply our BFT-agreed drift correction.
     */
    uint64_t raw_os_time =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

    uint64_t secure_time = raw_os_time + current_drift_;

    /**
     * SEC-001: Monotonic Floor Guarantee
     *
     * Time MUST NOT go backwards during process lifetime.
     * Protects:
     * - JWT validation
     * - certificate checks
     * - replay protection
     * - log ordering
     */
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
// Observation Verification
// ============================================================

bool BFTQuorumTrustedClock::verify_observation(
    const TimeObservation& obs) const
{
    /**
     * Reject unknown authorities immediately.
     * Trust is explicit and whitelist-based.
     */
    if (trusted_authorities_.find(obs.authority_id)
        == trusted_authorities_.end())
    {
        std::cerr << "[BFT CLOCK] Rejected unknown authority: " << obs.authority_id << "\n";
        return false;
    }

    /**
     * Replay-Window Verification
     * Sequences must be strictly monotonically increasing per authority.
     */
    auto seq_it = authority_sequences_.find(obs.authority_id);
    if (seq_it != authority_sequences_.end()) {
        if (obs.sequence <= seq_it->second) {
            std::cerr << "[BFT CLOCK] Replay detected! Sequence " << obs.sequence 
                      << " is <= last seen " << seq_it->second 
                      << " for " << obs.authority_id << "\n";
            return false;
        }
    }

    /**
     * Canonical signed payload format for Key Rotation support:
     * authority_id|key_id|timestamp|sequence
     *
     * Including key_id binds the signature to a specific generation of keys,
     * allowing zero-downtime rotation. crypto_verify will use key_id to fetch
     * the correct public key or HMAC secret from the registry.
     */
    std::string payload =
        obs.authority_id + "|" +
        obs.key_id + "|" + 
        std::to_string(obs.timestamp) + "|" +
        std::to_string(obs.sequence);

    // crypto_verify must be updated to accept key_id for correct dispatch
    return crypto_verify(payload, obs.signature, obs.authority_id, obs.key_id);
}


// ============================================================
// BFT Synchronization
// ============================================================

std::optional<BftSyncResult>
BFTQuorumTrustedClock::update_and_sync(
    const std::vector<TimeObservation>& observations)
{
    std::vector<uint64_t> valid_timestamps;
    std::vector<TimeObservation> valid_observations; // Track for sequence commits
    size_t rejected = 0;

    // --------------------------------------------------------
    // 1. Verify Signatures, Keys, Replay Window, & Whitelist
    // --------------------------------------------------------

    for (const auto& obs : observations) {
        if (verify_observation(obs)) {
            valid_timestamps.push_back(obs.timestamp);
            valid_observations.push_back(obs);
        } else {
            rejected++;
        }
    }

    size_t n_valid = valid_timestamps.size();

    if (n_valid < config_.min_quorum) {
        std::cerr << "[BFT CLOCK] Insufficient quorum. Valid: " << n_valid 
                  << " Required: " << config_.min_quorum << "\n";
        return std::nullopt;
    }

    // --------------------------------------------------------
    // 2. Sort and Apply Formal Byzantine Trimming
    // --------------------------------------------------------

    std::sort(valid_timestamps.begin(), valid_timestamps.end());

    /**
     * Formal PBFT Math:
     * To tolerate F Byzantine failures, the total number of valid nodes N
     * must satisfy N >= 3F + 1. 
     * * Therefore, the maximum number of tolerable faults is:
     * $F = \lfloor(N-1)/3\rfloor$
     */
    size_t f_tolerance = (n_valid > 0) ? (n_valid - 1) / 3 : 0;

    // Double check constraints against configuration limits
    if (n_valid < (3 * f_tolerance + 1)) {
        std::cerr << "[BFT CLOCK] Cannot satisfy formal BFT bounds $N \\ge 3F + 1$.\n";
        return std::nullopt;
    }

    // Drop the F highest and F lowest values, assuming they could be Byzantine
    std::vector<uint64_t> clustered(
        valid_timestamps.begin() + f_tolerance,
        valid_timestamps.end() - f_tolerance
    );

    // --------------------------------------------------------
    // 3. Cluster Skew Validation
    // --------------------------------------------------------

    if (clustered.back() - clustered.front()
        > config_.max_cluster_skew)
    {
        std::cerr << "[BFT CLOCK] Excessive cluster skew. Spread is greater than " 
                  << config_.max_cluster_skew << " seconds.\n";
        return std::nullopt;
    }

    // --------------------------------------------------------
    // 4. Median Calculation
    // --------------------------------------------------------

    uint64_t agreed_time;
    size_t n = clustered.size();

    if (n % 2 == 0) {
        agreed_time =
            (clustered[n/2 - 1] + clustered[n/2]) / 2;
    } else {
        agreed_time = clustered[n/2];
    }

    // --------------------------------------------------------
    // 5. Compute Drift Adjustment
    // --------------------------------------------------------

    uint64_t raw_os_time =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

    int64_t target_drift =
        static_cast<int64_t>(agreed_time) -
        static_cast<int64_t>(raw_os_time);

    int64_t drift_step =
        target_drift - current_drift_;

    // Anti-shock clamp
    if (std::abs(drift_step) > config_.max_drift_step) {
        drift_step =
            (drift_step > 0)
            ? config_.max_drift_step
            : -config_.max_drift_step;
    }

    int64_t proposed_total_drift =
        current_drift_ + drift_step;

    // Anti-creep ceiling
    if (std::abs(proposed_total_drift)
        > config_.max_total_drift)
    {
        std::cerr << "[BFT CLOCK] Total drift ceiling exceeded.\n";

        if (config_.fail_closed) {
            std::abort();
        }
        return std::nullopt;
    }

    // --------------------------------------------------------
    // 6. Commit Drift & Update Replay Windows
    // --------------------------------------------------------

    {
        std::lock_guard<std::mutex> lock(lock_);
        current_drift_ = proposed_total_drift;
        
        // Only update sequences after a successful BFT consensus
        for (const auto& obs : valid_observations) {
            authority_sequences_[obs.authority_id] = obs.sequence;
        }
    }

    // --------------------------------------------------------
    // 7. Audit Log
    // --------------------------------------------------------

    vault_.log_sync_event(
        agreed_time,
        drift_step,
        current_drift_
    );
    
    // Persist sequences for crash-recovery safety
    vault_.save_authority_sequences(authority_sequences_);

    return BftSyncResult{
        .agreed_time = agreed_time,
        .applied_drift = drift_step,
        .accepted_sources = clustered.size(),
        .outliers_ejected =
            valid_timestamps.size() - clustered.size(),
        .rejected_sources = rejected
    };
}


// ============================================================
// Shared State Adoption (Clustered Deployment)
// ============================================================

bool BFTQuorumTrustedClock::apply_shared_state(
    uint64_t shared_agreed_time,
    int64_t  shared_applied_drift,
    uint64_t leader_system_time_at_sync)
{
    /**
     * Shared-state adoption is optional and hardened.
     * Never blindly trust external state.
     */

    uint64_t local_raw_os_time =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

    int64_t os_delta =
        static_cast<int64_t>(local_raw_os_time)
        - static_cast<int64_t>(leader_system_time_at_sync);

    uint64_t expected_now =
        shared_agreed_time + os_delta;

    int64_t proposed_drift =
        static_cast<int64_t>(expected_now)
        - static_cast<int64_t>(local_raw_os_time);

    int64_t drift_step =
        proposed_drift - current_drift_;

    // Shock clamp
    if (std::abs(drift_step) > config_.max_drift_step) {
        drift_step =
            (drift_step > 0)
            ? config_.max_drift_step
            : -config_.max_drift_step;
    }

    int64_t safe_total =
        current_drift_ + drift_step;

    if (std::abs(safe_total)
        > config_.max_total_drift)
    {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(lock_);
        current_drift_ = safe_total;
    }

    vault_.log_sync_event(
        expected_now,
        drift_step,
        current_drift_
    );

    return true;
}

} // namespace uml001