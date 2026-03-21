#include "uml001/key_rotation_manager.h"
#include "uml001/vault.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/crypto_utils.h"

namespace uml001 {

// Constructor
KeyRotationManager::KeyRotationManager(
    std::shared_ptr<ColdVault> vault,
    const std::unordered_set<std::string>& authorities,
    Config config
) : vault_(std::move(vault)),
    authorities_(authorities),
    config_(config)
{
}

void KeyRotationManager::maybe_rotate(uint64_t strong_time) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (last_rotation_unix_ != 0 &&
        (strong_time - last_rotation_unix_ < config_.rotation_interval_seconds)) {
        return;
    }

    rotate_hmac(strong_time);
}

void KeyRotationManager::rotate_hmac(uint64_t strong_time) {
    previous_hmac_ = current_hmac_;
    previous_key_expiry_ = strong_time + config_.overlap_window_seconds;

    current_hmac_ = generate_random_bytes_hex(32);

    key_version_++;
    last_rotation_unix_ = strong_time;

    vault_->log_key_rotation_event(key_version_, strong_time);
}

bool KeyRotationManager::verify_with_overlap(
    const std::string& authority,
    const std::string& payload,
    const std::string& signature,
    uint64_t strong_time
) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (authorities_.find(authority) == authorities_.end()) {
        vault_->log_security_event("AUTH_FAILURE", "Unauthorized: " + authority);
        return false;
    }

    if (hmac_sha256_hex(current_hmac_, payload) == signature) {
        return true;
    }

    if (!previous_hmac_.empty() && strong_time <= previous_key_expiry_) {
        if (hmac_sha256_hex(previous_hmac_, payload) == signature) {
            return true;
        }
    }

    return false;
}

void KeyRotationManager::configure_fetcher(NtpObservationFetcher& fetcher) {
    std::lock_guard<std::mutex> lock(mutex_);
    fetcher.set_hmac_key(current_hmac_);
}

uint64_t KeyRotationManager::key_version() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return key_version_;
}

CryptoMode KeyRotationManager::mode() const {
    return config_.crypto.mode;
}

} // namespace uml001