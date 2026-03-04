/**
 * bft_quorum_clock.h
 *
 * Byzantine Fault Tolerant Trusted Clock — Shared State & Key Rotation
 * =====================================================================
 * Defines the core BFT clock engine. This header has been updated to 
 * support formal PBFT math ($F = \lfloor(N-1)/3\rfloor$), replay window 
 * tracking, and cryptographic key rotation.
 */

#pragma once

#include "vault.h" // Assumes ColdVault interface exists for auditing

#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <cstdint>

namespace uml001 {

struct TimeObservation {
    std::string authority_id;
    std::string key_id;       // Added for zero-downtime key rotation
    uint64_t    timestamp;
    std::string signature;
    uint64_t    sequence;
};

struct BftSyncResult {
    uint64_t agreed_time;
    int64_t  applied_drift;
    size_t   accepted_sources;
    size_t   outliers_ejected;
    size_t   rejected_sources;
};

class BFTQuorumTrustedClock {
public:
    struct Config {
        size_t   min_quorum           = 4;    // Increased to support 3F+1 with F=1
        uint64_t max_cluster_skew     = 5;    // Maximum seconds between clustered sources
        int64_t  max_drift_step       = 30;   // Max seconds clock can be corrected in one sync
        int64_t  max_total_drift      = 3600; // Total absolute drift allowed before failing
        uint64_t sequence_ttl_seconds = 300;  // Time before a sequence number check resets
        bool     fail_closed          = true; // If true, halt on security/bounds violations
    };

    BFTQuorumTrustedClock(
        Config config, 
        std::unordered_set<std::string> trusted_authorities,
        ColdVault& audit_vault);

    // Get the current secure time (Local OS time + current drift)
    uint64_t now_unix() const;

    // The primary worker method: Process raw NTP/Authority observations
    std::optional<BftSyncResult> update_and_sync(const std::vector<TimeObservation>& observations);

    // The shared state sync method: Apply a BFT consensus reached by a peer
    bool apply_shared_state(
        uint64_t shared_agreed_time, 
        int64_t  shared_applied_drift, 
        uint64_t leader_system_time_at_sync);

    // Return the current cumulative drift
    int64_t get_current_drift() const;

private:
    Config                          config_;
    std::unordered_set<std::string> trusted_authorities_;
    ColdVault&                      vault_;

    mutable std::mutex lock_;
    int64_t            current_drift_ = 0;
    mutable uint64_t   last_monotonic_read_ = 0; // mutable to allow updates in const now_unix()

    // Map to track the highest seen sequence number per authority to prevent replay attacks
    std::unordered_map<std::string, uint64_t> authority_sequences_;

    // Helper to verify cryptographic signatures, replay windows, and keys
    bool verify_observation(const TimeObservation& obs) const;
};

} // namespace uml001