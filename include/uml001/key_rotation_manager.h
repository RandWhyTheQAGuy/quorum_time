#pragma once

#include <string>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <memory>

#include "crypto_mode.h"

class ColdVault;
namespace uml001 { class NtpObservationFetcher; }

class KeyRotationManager {
public:

    struct Config {
        uint64_t rotation_interval_seconds = 3600;
        uint64_t overlap_window_seconds    = 180;
        CryptoConfig crypto;
    };

    KeyRotationManager(
        ColdVault& vault,
        const std::unordered_set<std::string>& authorities,
        Config config
    );

    void maybe_rotate(uint64_t strong_time);

    void configure_fetcher(uml001::NtpObservationFetcher& fetcher);

    bool verify_with_overlap(
        const std::string& authority,
        const std::string& payload,
        const std::string& signature,
        uint64_t strong_time
    );

    uint64_t key_version() const;
    CryptoMode mode() const;

private:
    void rotate_hmac(uint64_t strong_time);
    void rotate_ed25519(uint64_t strong_time);
    void rotate_tpm(uint64_t strong_time);

    bool verify_hmac(...);
    bool verify_ed25519(...);

    ColdVault& vault_;
    std::unordered_set<std::string> authorities_;
    Config config_;

    // HMAC
    std::string current_hmac_;
    std::string previous_hmac_;

    // Asymmetric
    std::string current_private_key_;
    std::string current_public_key_;
    std::string previous_public_key_;

    uint64_t previous_key_expiry_ = 0;
    uint64_t key_version_         = 0;
    uint64_t last_rotation_unix_  = 0;

    mutable std::mutex mutex_;
};