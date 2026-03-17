#pragma once

/**
 * @file ntp_observation_fetcher.h
 * @brief Byzantine-resilient NTP observation fetcher for the UML-001 trusted clock subsystem.
 */

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace uml001 {

// ============================================================
// Configuration Structures
// ============================================================

struct NtpServerEntry {
    std::string hostname;
    uint64_t    max_rtt_ms;
    uint32_t    timeout_ms;
};

// ============================================================
// Internal Observation Types
// ============================================================

struct NtpObservation {
    std::string server_hostname;
    uint64_t    unix_seconds;
    uint64_t    rtt_ms;
    uint8_t     stratum;
    bool        is_outlier;
};

struct TimeObservation {
    std::string server_hostname;
    std::string key_id;
    uint64_t    unix_seconds;
    std::string signature_hex;
    uint64_t    sequence;
};

// ============================================================
// Quorum Attestation Token
// ============================================================

struct TimestampAttestationToken {
    uint64_t                 unix_time;
    uint64_t                 median_rtt;
    uint64_t                 drift_ppm;
    std::vector<std::string> quorum_servers;
    std::string              quorum_hash;
    std::string              signature;
};

// ============================================================
// NtpObservationFetcher
// ============================================================

class NtpObservationFetcher {
public:
    NtpObservationFetcher(
        std::string                 hmac_key,
        std::string                 key_id,
        std::vector<NtpServerEntry> servers,
        uint8_t                     stratum_max,
        size_t                      quorum_size,
        uint64_t                    outlier_threshold_s = 2
    );

    ~NtpObservationFetcher();

    // Query all configured NTP servers and return signed observations.
    std::vector<TimeObservation> fetch();

    // Dynamic key rotation (zero downtime).
    // new_hmac_key is raw 32-byte key material; new_key_id is the generation id ("v2", etc.).
    void set_hmac_key(std::string new_hmac_key,
                      std::string new_key_id);

    // Persist per-server sequence counters for cross-restart anti-replay.
    // Simple text format: "hostname=seq\n" per line.
    std::string save_sequence_state() const;

private:
    std::optional<NtpObservation>
    query_server(const NtpServerEntry& server) const;

    TimeObservation sign_observation(const NtpObservation& raw);

    bool is_byzantine_outlier(
        uint64_t                     value,
        const std::vector<uint64_t>& values
    ) const;

    uint64_t median(std::vector<uint64_t> values) const;

    uint64_t estimate_drift(uint64_t new_time);

    std::optional<TimestampAttestationToken>
    build_quorum_token(const std::vector<NtpObservation>& obs);

    // Immutable configuration
    std::string                 hmac_key_;   // binary, 32 bytes
    std::string                 key_id_;
    std::vector<NtpServerEntry> servers_;
    uint8_t                     stratum_max_;
    size_t                      quorum_size_;
    uint64_t                    outlier_threshold_s_;

    // Mutable state — protected by seq_mutex_
    mutable std::mutex seq_mutex_;
    std::unordered_map<std::string, uint64_t> sequences_;

    // Mutable state — protected by drift_mutex_
    std::mutex drift_mutex_;
    uint64_t   last_reference_time_{0};
    uint64_t   last_local_time_{0};
};

} // namespace uml001
