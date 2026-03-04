/**
 * main_sidecar.cpp
 *
 * BFT Trusted Clock — HTTP Sidecar Deployment
 * ===========================================
 * This application initializes the BFT Quorum Clock and exposes it
 * over a local HTTP REST API. It is designed to run as a sidecar
 * container in a Kubernetes Pod alongside the primary microservice.
 *
 * Endpoints:
 * GET /api/v1/time   -> Returns the secure BFT time and drift.
 * GET /health        -> Liveness probe (fails if max drift exceeded).
 */

#include "bft_quorum_clock.h"
#include "ntp_observation_fetcher.h"
#include "vault.h"
#include "crypto_utils.h"

// Header-only dependencies
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <thread>
#include <atomic>
#include <iostream>
#include <memory>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Background Sync Loop (Adapted from previous implementation)
// ---------------------------------------------------------------------------
static void run_sidecar_sync_loop(
    std::shared_ptr<uml001::BFTQuorumTrustedClock> clock,
    std::shared_ptr<uml001::NtpObservationFetcher> fetcher,
    std::atomic<bool>& shutdown)
{
    const int sync_interval_s = 60;
    
    while (!shutdown.load(std::memory_order_acquire)) {
        try {
            auto observations = fetcher->fetch();
            if (!observations.empty()) {
                auto result = clock->update_and_sync(observations);
                if (result.has_value()) {
                    std::cout << "[SIDECAR SYNC] Consensus reached: " 
                              << result->agreed_time << "\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[SIDECAR ERROR] Sync failed: " << e.what() << "\n";
        }

        // Sleep in small increments to allow responsive shutdown
        for (int i = 0; i < sync_interval_s * 2 && !shutdown; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

// ---------------------------------------------------------------------------
// Main Sidecar Entrypoint
// ---------------------------------------------------------------------------
int main() {
    std::cout << "[SIDECAR] Initializing BFT Trusted Clock...\n";

    // 1. Initialize Storage and Cryptography
    uml001::ColdVault vault("/var/lib/bft-clock/audit.vault");
    const std::string hmac_key = uml001::generate_random_bytes_hex(32);

    // 2. Configure Authorities
    std::unordered_set<std::string> ntp_authorities = {
        "time.cloudflare.com", "time.google.com", "time.nist.gov", "time.apple.com"
    };
    for (const auto& host : ntp_authorities) {
        uml001::register_hmac_authority(host, hmac_key);
    }

    // 3. Initialize Fetcher and Clock
    auto fetcher = std::make_shared<uml001::NtpObservationFetcher>(
        hmac_key, uml001::NtpObservationFetcher::default_server_pool()
    );

    uml001::BFTQuorumTrustedClock::Config cfg;
    cfg.min_quorum = 3;
    cfg.max_total_drift = 3600; // 1 hour max drift allowed
    
    auto bft_clock = std::make_shared<uml001::BFTQuorumTrustedClock>(
        cfg, ntp_authorities, vault
    );

    // 4. Start Background Sync Thread
    std::atomic<bool> shutdown{false};
    std::thread sync_thread(run_sidecar_sync_loop, bft_clock, fetcher, std::ref(shutdown));

    // 5. Setup HTTP Server (Localhost only)
    httplib::Server svr;

    // REST API: Get Secure Time
    svr.Get("/api/v1/time", [&](const httplib::Request&, httplib::Response& res) {
        try {
            uint64_t secure_time = bft_clock->now_unix();
            int64_t current_drift = bft_clock->get_current_drift();

            json response = {
                {"status", "success"},
                {"data", {
                    {"secure_time_unix", secure_time},
                    {"applied_drift_seconds", current_drift},
                    {"is_degraded", false}
                }}
            };
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            json error = {{"status", "error"}, {"message", e.what()}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // REST API: Kubernetes Liveness/Readiness Probe
    svr.Get("/health", [&](const httplib::Request&, httplib::Response& res) {
        // If the drift exceeds safety bounds, mark the sidecar as unhealthy.
        // Kubernetes will automatically restart the pod or route traffic away.
        int64_t drift = std::abs(bft_clock->get_current_drift());
        if (drift > cfg.max_total_drift) {
            res.status = 503; // Service Unavailable
            res.set_content("{\"status\": \"unhealthy\", \"reason\": \"drift_bounds_exceeded\"}", "application/json");
        } else {
            res.status = 200; // OK
            res.set_content("{\"status\": \"healthy\"}", "application/json");
        }
    });

    // 6. Bind to 127.0.0.1 (Loopback) so ONLY local containers in the same Pod can query it
    int port = 9090;
    std::cout << "[SIDECAR] Listening strictly on 127.0.0.1:" << port << "\n";
    svr.listen("127.0.0.1", port);

    // 7. Graceful Shutdown
    shutdown.store(true);
    if (sync_thread.joinable()) {
        sync_thread.join();
    }

    return 0;
}