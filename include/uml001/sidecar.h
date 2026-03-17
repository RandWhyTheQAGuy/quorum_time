#pragma once
/**
 * sidecar.h
 *
 * BFT Trusted Clock — HTTP Sidecar Interface
 * ==========================================
 * Declares the public-facing components used by main_sidecar.cpp:
 *
 *  - run_sidecar_sync_loop(): background NTP/BFT sync thread
 *  - SidecarConfig: runtime configuration for the sidecar
 *
 * This header intentionally avoids pulling in heavy dependencies
 * (httplib, nlohmann/json, etc.) to keep compile boundaries clean.
 */

#include <memory>
#include <atomic>
#include <unordered_set>
#include <string>

namespace uml001 {

class BFTQuorumTrustedClock;
class NtpObservationFetcher;

/**
 * SidecarConfig
 *
 * Runtime configuration for the BFT clock sidecar.
 * These values are typically injected via environment variables
 * or Kubernetes ConfigMaps.
 */
struct SidecarConfig {
    int     sync_interval_s   = 60;     // How often to run BFT sync
    int     max_total_drift_s = 3600;   // Drift threshold for /health
    int     http_port         = 9090;   // Local REST API port
    bool    bind_localhost    = true;   // Restrict to 127.0.0.1
};

/**
 * run_sidecar_sync_loop()
 *
 * Background thread that:
 *   - Fetches NTP observations
 *   - Runs BFT consensus
 *   - Applies drift updates
 *   - Logs sync results
 *
 * The loop exits when `shutdown` becomes true.
 */
void run_sidecar_sync_loop(
    std::shared_ptr<BFTQuorumTrustedClock> clock,
    std::shared_ptr<NtpObservationFetcher> fetcher,
    std::atomic<bool>& shutdown);

} // namespace uml001
