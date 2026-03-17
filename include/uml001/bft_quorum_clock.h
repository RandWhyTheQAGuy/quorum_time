#pragma once

/**
 * @file bft_quorum_clock.h
 * @brief BFT quorum trusted clock — requires f+1 agreeing authorities
 *        to advance trusted time.
 *
 * Security invariants:
 *   - Trusted time only advances when >= min_quorum observations agree
 *   - Per-authority sequence numbers prevent replay attacks
 *   - All rejections (unknown authority, bad signature, replay, quorum
 *     failure, drift ceiling exceeded) are logged to the ColdVault
 *   - fail_closed=true halts the clock rather than returning unverified
 *     time on quorum loss
 *   - verify_observation() is public so Python bindings and external
 *     callers can validate individual observations before submitting
 *     a batch to update_and_sync()
 *
 * [FIX-11] verify_observation moved from private to public so it can be
 *           bound in uml001_bindings.cpp and called from Python tests.
 */

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "uml001/ntp_observation_fetcher.h"
#include "uml001/crypto_utils.h"
#include "uml001/strong_clock.h"
#include "uml001/vault.h"

namespace uml001 {

struct BftClockConfig {
    int64_t  max_drift_step    = 2;   // Max drift applied per sync round (seconds)
    int64_t  max_total_drift   = 60;  // Max cumulative drift allowed (seconds)
    uint64_t max_cluster_skew  = 5;   // Max acceptable spread among quorum (seconds)
    size_t   min_quorum        = 4;   // Minimum agreeing authorities required
    bool     fail_closed       = false; // If true, halt on quorum loss
};

struct BftSyncResult {
    uint64_t agreed_time      = 0;  // Consensus unix timestamp
    int64_t  applied_drift    = 0;  // Drift adjustment applied this round
    size_t   accepted_sources = 0;  // Number of observations accepted
    size_t   outliers_ejected = 0;  // Number of observations rejected as outliers
    size_t   rejected_sources = 0;  // Number of observations rejected for other reasons
};

class BFTQuorumTrustedClock : public IStrongClock {
public:
    BFTQuorumTrustedClock(
        BftClockConfig                   config,
        std::unordered_set<std::string>  trusted_authorities,
        ColdVault&                       audit_vault
    );

    ~BFTQuorumTrustedClock() override = default;

    BFTQuorumTrustedClock(const BFTQuorumTrustedClock&)            = delete;
    BFTQuorumTrustedClock& operator=(const BFTQuorumTrustedClock&) = delete;

    // --------------------------------------------------------
    // IStrongClock interface
    // --------------------------------------------------------

    uint64_t now_unix() const override;
    int64_t  get_current_drift() const override;

    // --------------------------------------------------------
    // Synchronisation
    // --------------------------------------------------------

    /**
     * @brief Ingest a batch of observations, validate quorum, and advance
     *        trusted time if the round succeeds.
     *
     * @param observations      Signed observations from NTP authorities.
     * @param current_warp_score Warp score [0.0, 1.0] that reduces the
     *                           dynamic drift ceiling proportionally.
     *                           0.0 = full ceiling; 1.0 = no drift allowed.
     * @return BftSyncResult if the round succeeded, std::nullopt otherwise.
     *         All failures are logged to the vault.
     */
    std::optional<BftSyncResult> update_and_sync(
        const std::vector<TimeObservation>& observations,
        double                              current_warp_score = 0.0
    );

    /**
     * @brief Apply a pre-agreed cluster state signed by the leader node.
     *
     * Used in multi-node deployments where one node acts as sync leader
     * and followers apply its signed state rather than running independent
     * BFT rounds.
     */
    bool apply_shared_state(
        uint64_t           shared_agreed_time,
        int64_t            shared_applied_drift,
        uint64_t           leader_system_time_at_sync,
        const std::string& signature_hex,
        const std::string& leader_id,
        const std::string& key_id,
        double             current_warp_score = 0.0
    );

    // --------------------------------------------------------
    // Observation verification
    //
    // [FIX-11] Moved from private to public.
    //
    // Validates a single observation against:
    //   1. Authority membership — rejects unknown authorities
    //   2. HMAC signature      — rejects tampered or forged observations
    //   3. Sequence number     — rejects replayed observations
    //
    // All rejections are logged to the vault as security events so that
    // every verification failure is auditable.
    //
    // Returns true only if all three checks pass.
    // --------------------------------------------------------

    bool verify_observation(const TimeObservation& obs) const;

private:
    // Dynamic drift limit helpers — scale ceiling/step by warp score
    int64_t get_dynamic_drift_ceiling(double warp_score) const;
    int64_t get_dynamic_drift_step(double warp_score) const;

    // Configuration and dependencies (set at construction, never mutated)
    const BftClockConfig                  config_;
    const std::unordered_set<std::string> trusted_authorities_;
    ColdVault&                            vault_;

    // Clock state — protected by lock_
    mutable std::mutex lock_;

    int64_t          current_drift_        = 0;
    mutable uint64_t last_monotonic_read_  = 0;

    // Per-authority sequence numbers for replay prevention
    std::unordered_map<std::string, uint64_t> authority_sequences_;
};

} // namespace uml001