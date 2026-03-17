/**
 * @file main_ntp.cpp
 * @brief Standalone NTP-based BFT trusted clock daemon.
 *
 * This program wires together:
 *   - A simple filesystem-backed ColdVault for tamper-evident audit logs
 *   - A simple hash provider and strong clock implementation
 *   - An NTP observation fetcher with optional HMAC protection
 *   - A BFT quorum trusted clock
 *   - A key rotation manager
 *   - A background sync loop that coordinates local BFT time and shared state
 */

#include "uml001/strong_clock.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/vault.h"
#include "uml001/crypto_utils.h"
#include "uml001/vault_logger.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"

#include <unordered_set>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <optional>
#include <mutex>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

// ============================================================
// Minimal backend + hash provider + strong clock for ColdVault
// ============================================================


// ============================================================
// Shared Cluster State
// ============================================================

/**
 * @struct SharedClockState
 * @brief Represents the shared cluster time state stored in Redis (or similar).
 *
 * Fields:
 *   - agreed_time:      The BFT-agreed cluster time at last sync
 *   - applied_drift:    The drift applied by the leader at that sync
 *   - last_updated_unix:The strong time when the state was last updated
 *   - key_version:      The HMAC key version used for the observations
 */
struct SharedClockState {
    uint64_t agreed_time;
    int64_t  applied_drift;
    uint64_t last_updated_unix;
    uint64_t key_version;
};

/**
 * @class RedisSharedStore
 * @brief Minimal in-memory stand-in for a Redis-backed shared state store.
 *
 * In production, this would:
 *   - Use WATCH/MULTI/EXEC semantics
 *   - Handle CAS and conflict resolution
 *   - Persist state across restarts
 */
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
// Key Rotation Manager
// ============================================================

/**
 * @class KeyRotationManager
 * @brief Manages periodic HMAC key rotation for NTP authorities.
 *
 * Responsibilities:
 *   - Generate new HMAC keys at a configured interval
 *   - Maintain an overlap window where the previous key remains valid
 *   - Register keys with the crypto layer for each authority
 *   - Log key rotation events to the ColdVault
 */
class KeyRotationManager {
public:
    KeyRotationManager(
        uml001::ColdVault& vault,
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
            current_key_    = uml001::generate_random_bytes_hex(32);
            key_version_    = 1;
            current_key_id_ = "v" + std::to_string(key_version_);
        }
    }

    /**
     * @brief Rotate keys if the rotation interval has elapsed.
     *
     * This:
     *   - Promotes current key to "previous"
     *   - Generates a new current key
     *   - Registers the new key for all authorities
     *   - Logs the rotation event to the vault
     */
    void maybe_rotate(uint64_t strong_time) {
        if (!use_hmac_) return;

        std::lock_guard<std::mutex> lock(mutex_);

        if (last_rotation_unix_ == 0)
            last_rotation_unix_ = strong_time;

        if ((strong_time - last_rotation_unix_) < rotation_interval_s_)
            return;

        previous_key_        = current_key_;
        previous_key_id_     = current_key_id_;
        previous_key_expiry_ = strong_time + overlap_window_s_;

        current_key_    = uml001::generate_random_bytes_hex(32);
        key_version_++;
        current_key_id_ = "v" + std::to_string(key_version_);

        last_rotation_unix_ = strong_time;

        for (const auto& a : authorities_) {
            uml001::register_hmac_authority(a, current_key_id_, current_key_);
        }

        vault_.log_key_rotation_event(key_version_, strong_time);

        std::cout << "[KEY ROTATION] Rotated key. Version="
                  << key_version_
                  << " Overlap until "
                  << previous_key_expiry_
                  << "\n";
    }

    /**
     * @brief Configure an NtpObservationFetcher with the current HMAC key.
     */
    void configure_fetcher(uml001::NtpObservationFetcher& fetcher) {
        if (!use_hmac_) return;
        fetcher.set_hmac_key(current_key_, current_key_id_);
    }

    /**
     * @brief Return the current key version.
     */
    uint64_t key_version() const {
        return key_version_;
    }

private:
    uml001::ColdVault& vault_;
    std::unordered_set<std::string> authorities_;

    uint64_t rotation_interval_s_;
    uint64_t overlap_window_s_;
    bool use_hmac_;

    std::string current_key_;
    std::string previous_key_;
    std::string current_key_id_;
    std::string previous_key_id_;

    uint64_t previous_key_expiry_ = 0;
    uint64_t key_version_         = 0;
    uint64_t last_rotation_unix_  = 0;

    mutable std::mutex mutex_;
};

// ============================================================
// Background Sync Loop
// ============================================================

/**
 * @brief Background loop that periodically:
 *   - Rotates keys
 *   - Reads shared cluster state
 *   - Either adopts shared state or performs a fresh BFT sync
 *   - Publishes new shared state when local node is leader
 *
 * This function is intended to run in its own thread.
 */
static void background_sync_loop(
    uml001::BFTQuorumTrustedClock& clock,
    uml001::NtpObservationFetcher& fetcher,
    uml001::ColdVault& vault,
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

        // Periodically rotate HMAC keys
        key_manager.maybe_rotate(strong_time);

        // Read shared cluster state (if any)
        auto shared_state = redis_store.read_state();

        // If shared state is stale, log degradation
        if (shared_state.has_value()) {
            if ((strong_time - shared_state->last_updated_unix) > degradation_window_s) {
                uml001::vault_log("clock.degradation", "shared state stale");
            }
        }

        // Only perform a full sync every interval_s
        if (++tick_count < ticks_total) continue;
        tick_count = 0;

        try {
            // If shared state is fresh enough, adopt it instead of re-syncing
            if (shared_state.has_value() &&
                (strong_time - shared_state->last_updated_unix) < interval_s / 2)
            {
                clock.apply_shared_state(
                    shared_state->agreed_time,
                    shared_state->applied_drift,
                    shared_state->last_updated_unix,
                    "",      // signature_hex (omitted in this demo)
                    "local", // leader_id (placeholder)
                    "v1",    // key_id (placeholder)
                    0.0      // warp_score
                );
                continue;
            }

            // Otherwise, perform a fresh BFT sync using NTP observations
            key_manager.configure_fetcher(fetcher);

            auto observations = fetcher.fetch();
            if (observations.empty()) continue;

            auto result = clock.update_and_sync(observations);
            if (result.has_value()) {

                SharedClockState new_state {
                    result->agreed_time,
                    result->applied_drift,
                    strong_time,
                    key_manager.key_version()
                };

                if (redis_store.watch_and_commit(new_state)) {
                    uml001::vault_log("clock.sync", "promoted BFT time");
                }
            }
        }
        catch (const std::exception& ex) {
            uml001::vault_log("clock.sync.error", ex.what());
        }
    }
}

// ============================================================
// MAIN
// ============================================================

/**
 * @brief Entry point for the NTP-based BFT trusted clock daemon.
 *
 * Responsibilities:
 *   - Construct ColdVault and its backend
 *   - Install a vault logger hook
 *   - Configure NTP authorities and HMAC keys
 *   - Construct BFTQuorumTrustedClock and NtpObservationFetcher
 *   - Launch the background sync loop
 */
int main() {

    // Strong clock and hash provider used by ColdVault
    uml001::OsStrongClock strong_clock;
    uml001::SimpleHashProvider hash_provider;

    // Configure ColdVault
    uml001::ColdVault::Config vault_cfg;
    vault_cfg.base_directory       = "var/uml001/clock_audit.vault";
    vault_cfg.max_file_size_bytes  = 10 * 1024 * 1024;
    vault_cfg.max_file_age_seconds = 86400;
    vault_cfg.fsync_on_write       = true;

    auto backend =
    std::make_unique<uml001::SimpleFileVaultBackend>(vault_cfg.base_directory);
    uml001::ColdVault vault(vault_cfg, std::move(backend), strong_clock, hash_provider);

    // Install vault logger: route generic vault_log(key, value) into ColdVault
    uml001::set_vault_logger(
        [&vault](const std::string& key, const std::string& value) {
            // New vault API: separate key and detail
            vault.log_security_event(key, value);
        }
    );

    // In-memory stand-in for a shared store (e.g., Redis)
    RedisSharedStore redis_store;

    // ============================================================
    // Global Hardened NTP Authority Registry
    // ============================================================
    //
    // Purpose
    // -------
    // Large geographically distributed NTP authority set intended
    // for Byzantine Fault Tolerant quorum clocks.
    //
    // Design principles:
    //   • <= 5 hosts per country
    //   • Prefer national metrology institutes
    //   • Prefer research network stratum-1 nodes
    //   • Use NTP pool only as tertiary fallback
    //   • Multi-continent diversity
    //
    // Regions:
    //   - North America
    //   - Europe
    //   - Asia-Pacific
    //   - Oceania
    //

    std::unordered_set<std::string> ntp_authorities = {

    // ========================================================
    // NORTH AMERICA
    // ========================================================

        // ---------- United States ----------
        "time.cloudflare.com",   // Cloudflare public NTP
        "time.google.com",       // Google Public NTP
        "time.windows.com",      // Microsoft NTP
        "time.apple.com",        // Apple NTP
        "time.nist.gov",         // NIST official time service

        // ---------- Canada ----------
        "time.nrc.ca",           // National Research Council
        "time.chu.nrc.ca",       // NRC radio time service
        "0.ca.pool.ntp.org",     // Canadian pool shard
        "1.ca.pool.ntp.org",     // Canadian pool shard


        // ========================================================
        // EUROPE
        // ========================================================

        // ---------- United Kingdom ----------
        "ntp0.zen.co.uk",        // UK ISP operated NTP
        "ntp1.zen.co.uk",
        "uk.pool.ntp.org",
        "0.uk.pool.ntp.org",

        // ---------- Germany ----------
        "ptbtime1.ptb.de",       // PTB national metrology institute
        "ptbtime2.ptb.de",
        "0.de.pool.ntp.org",
        "1.de.pool.ntp.org",

        // ---------- France ----------
        "ntp.obspm.fr",          // Paris Observatory
        "ntp1.obspm.fr",
        "0.fr.pool.ntp.org",
        "1.fr.pool.ntp.org",

        // ---------- Netherlands ----------
        "ntp1.nl.net",           // NLnet Labs
        "ntp2.nl.net",
        "0.nl.pool.ntp.org",
        "1.nl.pool.ntp.org",

        // ---------- Switzerland ----------
        "ntp.metas.ch",          // Federal Institute of Metrology
        "ntp1.metas.ch",
        "0.ch.pool.ntp.org",

        // ---------- Italy ----------
        "ntp1.inrim.it",         // Italian National Metrology Institute
        "ntp2.inrim.it",
        "0.it.pool.ntp.org",
        "1.it.pool.ntp.org",

        // ---------- Sweden ----------
        "ntp1.sp.se",            // RISE Research Institutes
        "ntp2.sp.se",
        "0.se.pool.ntp.org",

        // ---------- Norway ----------
        "time.met.no",           // Norwegian Meteorological Institute
        "ntp.uninett.no",        // UNINETT research network
        "0.no.pool.ntp.org",

        // ---------- Finland ----------
        "ntp1.funet.fi",         // Finnish research network
        "ntp2.funet.fi",
        "0.fi.pool.ntp.org",

        // ---------- Poland ----------
        "tempus1.gum.gov.pl",    // Central Office of Measures
        "ntp.task.gda.pl",       // Academic Computer Center
        "0.pl.pool.ntp.org",


        // ========================================================
        // ASIA
        // ========================================================

        // ---------- Japan ----------
        "ntp.nict.jp",           // National Institute of ICT
        "ntp1.nict.jp",
        "ntp2.nict.jp",
        "0.jp.pool.ntp.org",

        // ---------- South Korea ----------
        "time.kriss.re.kr",      // Korea Research Institute of Standards
        "ntp.kriss.re.kr",
        "0.kr.pool.ntp.org",

        // ---------- Singapore ----------
        "ntp1.singnet.com.sg",   // Singapore ISP NTP
        "ntp2.singnet.com.sg",
        "0.sg.pool.ntp.org",

        // ---------- Taiwan ----------
        "clock.stdtime.gov.tw",  // Taiwan standard time service
        "tick.stdtime.gov.tw",
        "0.tw.pool.ntp.org",


        // ========================================================
        // OCEANIA
        // ========================================================

        // ---------- Australia ----------
        "time.australia.gov.au", // Australian government official time
        "ntp.csiro.au",          // CSIRO research network
        "0.au.pool.ntp.org",
        "1.au.pool.ntp.org",

        // ---------- New Zealand ----------
        "ntp.net.nz",            // NZ research network
        "time.waikato.ac.nz",    // University of Waikato
        "0.nz.pool.ntp.org"

    };

    bool use_hmac = true;

    // Key rotation manager for HMAC keys
    KeyRotationManager key_manager(
        vault,
        ntp_authorities,
        3600, // rotation interval (seconds)
        180,  // overlap window (seconds)
        use_hmac
    );

    // NTP servers configuration
    std::vector<uml001::NtpServerEntry> servers = {
        { "time.cloudflare.com", 1000, 2000 },
        { "time.google.com",     1000, 2000 },
        { "time.windows.com",    1000, 2000 },
        { "time.apple.com",      1000, 2000 },
        { "time.nist.gov",       1000, 2000 }
    };

    // Initial HMAC key material
    std::string initial_key    = use_hmac ? uml001::generate_random_bytes_hex(32) : "";
    std::string initial_key_id = "v1";

    if (use_hmac) {
        for (const auto& a : ntp_authorities) {
            uml001::register_hmac_authority(a, initial_key_id, initial_key);
        }
    }

    // NTP observation fetcher
    uml001::NtpObservationFetcher fetcher(
        initial_key,
        initial_key_id,
        servers,
        2, // max stratum
        3, // quorum size
        2  // outlier threshold (seconds)
    );

    // BFT clock configuration
    uml001::BftClockConfig cfg;
    cfg.min_quorum       = 15; // Increase to 19+ for Financial Grade
    cfg.max_cluster_skew = 5;
    cfg.max_drift_step   = 30;
    cfg.max_total_drift  = 3600;
    cfg.fail_closed      = true;

    // BFT quorum trusted clock
    uml001::BFTQuorumTrustedClock bft_clock(cfg, ntp_authorities, vault);

    // Background sync control
    std::atomic<bool> shutdown{false};

    // Launch background sync loop in a separate thread
    std::thread sync_thread([&]() {
        background_sync_loop(
            bft_clock,
            fetcher,
            vault,
            redis_store,
            key_manager,
            60,  // sync interval (seconds)
            120, // degradation window (seconds)
            shutdown
        );
    });

    // Let it run for a short demo period, then shut down
    std::this_thread::sleep_for(std::chrono::seconds(5));
    shutdown.store(true, std::memory_order_release);
    sync_thread.join();

    return 0;
}
