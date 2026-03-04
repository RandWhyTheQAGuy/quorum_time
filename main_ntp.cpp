#include "strong_clock.h"
#include "bft_quorum_clock.h"
#include "ntp_observation_fetcher.h"
#include "vault.h"
#include "crypto_utils.h"

#include <unordered_set>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <optional>
#include <mutex>

// ============================================================
// Shared Cluster State (Versioned + Key Versioned)
// ============================================================

struct SharedClockState {
    uint64_t agreed_time;
    int64_t  applied_drift;
    uint64_t last_updated_unix;
    uint64_t key_version;
};

class RedisSharedStore {
public:
    std::optional<SharedClockState> read_state() {
        return cached_state_;
    }

    bool watch_and_commit(const SharedClockState& new_state) {
        cached_state_ = new_state;
        return true;
    }

private:
    std::optional<SharedClockState> cached_state_;
};

// ============================================================
// Key Rotation Manager (Dual-Key Overlap + Optional HMAC)
// ============================================================

class KeyRotationManager {
public:
    KeyRotationManager(
        ColdVault& vault,
        const std::unordered_set<std::string>& authorities,
        uint64_t rotation_interval_seconds,
        uint64_t overlap_window_seconds,
        bool use_hmac)
        : vault_(vault),
          authorities_(authorities),
          rotation_interval_s_(rotation_interval_seconds),
          overlap_window_s_(overlap_window_seconds),
          use_hmac_(use_hmac)
    {
        if (use_hmac_) {
            current_key_ = generate_random_bytes_hex(32);
            key_version_ = 1;
        }
    }

    void maybe_rotate(uint64_t strong_time) {
        if (!use_hmac_) return;

        std::lock_guard<std::mutex> lock(mutex_);

        if (last_rotation_unix_ == 0)
            last_rotation_unix_ = strong_time;

        if ((strong_time - last_rotation_unix_) < rotation_interval_s_)
            return;

        previous_key_ = current_key_;
        previous_key_expiry_ = strong_time + overlap_window_s_;

        current_key_ = generate_random_bytes_hex(32);
        key_version_++;

        last_rotation_unix_ = strong_time;

        for (const auto& a : authorities_) {
            register_hmac_authority(a, current_key_);
        }

        vault_.log_key_rotation_event(key_version_, strong_time);

        std::cout << "[KEY ROTATION] Rotated key. Version="
                  << key_version_
                  << " Overlap until "
                  << previous_key_expiry_
                  << "\n";
    }

    void configure_fetcher(uml001::NtpObservationFetcher& fetcher) {
        if (!use_hmac_) return;
        fetcher.set_hmac_key(current_key_);
    }

    bool verify_with_overlap(const std::string& authority,
                             const std::string& payload,
                             const std::string& signature,
                             uint64_t strong_time)
    {
        if (!use_hmac_)
            return true;

        if (crypto_verify(payload, signature, authority, current_key_))
            return true;

        if (!previous_key_.empty() &&
            strong_time <= previous_key_expiry_)
        {
            return crypto_verify(payload, signature, authority, previous_key_);
        }

        return false;
    }

    uint64_t key_version() const {
        return key_version_;
    }

private:
    ColdVault& vault_;
    std::unordered_set<std::string> authorities_;

    uint64_t rotation_interval_s_;
    uint64_t overlap_window_s_;
    bool use_hmac_;

    std::string current_key_;
    std::string previous_key_;

    uint64_t previous_key_expiry_ = 0;
    uint64_t key_version_ = 0;
    uint64_t last_rotation_unix_ = 0;

    mutable std::mutex mutex_;
};


// ============================================================
// Background Sync Loop
// ============================================================

static void background_sync_loop(
    uml001::BFTQuorumTrustedClock& clock,
    uml001::NtpObservationFetcher& fetcher,
    ColdVault& vault,
    RedisSharedStore& redis_store,
    KeyRotationManager& key_manager,
    uint64_t interval_s,
    uint64_t degradation_window_s,
    std::atomic<bool>& shutdown)
{
    const auto tick = std::chrono::milliseconds(500);
    const int ticks_total = static_cast<int>((interval_s * 1000) / tick.count());
    int tick_count = ticks_total;

    while (!shutdown.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(tick);

        uint64_t strong_time = clock.now_unix();

        key_manager.maybe_rotate(strong_time);

        auto shared_state = redis_store.read_state();

        if (shared_state.has_value()) {
            if ((strong_time - shared_state->last_updated_unix) > degradation_window_s) {
                std::cerr << "[DEGRADATION WARN] Shared clock state stale.\n";
            }
        }

        if (++tick_count < ticks_total) continue;
        tick_count = 0;

        try {
            if (shared_state.has_value() &&
                (strong_time - shared_state->last_updated_unix) < interval_s / 2)
            {
                clock.apply_shared_state(
                    shared_state->agreed_time,
                    shared_state->applied_drift,
                    shared_state->last_updated_unix
                );
                continue;
            }

            key_manager.configure_fetcher(fetcher);

            auto observations = fetcher.fetch();
            if (observations.empty()) continue;

            auto result = clock.update_and_sync(observations);
            if (result.has_value()) {

                SharedClockState new_state {
                    .agreed_time = result->agreed_time,
                    .applied_drift = result->applied_drift,
                    .last_updated_unix = strong_time,
                    .key_version = key_manager.key_version()
                };

                if (redis_store.watch_and_commit(new_state)) {
                    vault.persist_ntp_sequences(fetcher.save_sequence_state());
                    std::cout << "[CLOCK SYNC] Promoted BFT time.\n";
                }
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "[CLOCK SYNC ERROR] " << ex.what() << "\n";
        }
    }
}


// ============================================================
// MAIN
// ============================================================

int main() {

    ColdVault vault("var/uml001/clock_audit.vault");
    RedisSharedStore redis_store;

    std::unordered_set<std::string> ntp_authorities = {
        "time.cloudflare.com",
        "time.google.com",
        "time.windows.com",
        "time.apple.com",
        "time.nist.gov"
    };

    bool use_hmac = true;

    KeyRotationManager key_manager(
        vault,
        ntp_authorities,
        3600,  // rotate hourly
        180,   // 3 minute overlap window
        use_hmac
    );

    uml001::NtpObservationFetcher fetcher(
        use_hmac ? generate_random_bytes_hex(32) : "",
        uml001::NtpObservationFetcher::default_server_pool(),
        3
    );

    uml001::BFTQuorumTrustedClock::Config cfg;
    cfg.min_quorum       = 3;
    cfg.max_cluster_skew = 5;
    cfg.max_drift_step   = 30;
    cfg.max_total_drift  = 3600;
    cfg.fail_closed      = true;

    uml001::BFTQuorumTrustedClock bft_clock(cfg, ntp_authorities, vault);

    std::atomic<bool> shutdown{false};

    std::thread sync_thread([&]() {
        background_sync_loop(
            bft_clock,
            fetcher,
            vault,
            redis_store,
            key_manager,
            60,
            120,
            shutdown
        );
    });

    std::this_thread::sleep_for(std::chrono::seconds(5));
    shutdown.store(true, std::memory_order_release);
    sync_thread.join();

    return 0;
}