/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "uml001/bft_quorum_clock.h"
#include "uml001/crypto_utils.h"
#include "uml001/event_orchestrator.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/os_strong_clock.h"
#include "uml001/pipeline_bootstrap.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/vault.h"
#include "uml001/governor.h"
#include "proto/signed_state.pb.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace uml001 {

class IGossipProvider;

/**
 * @brief Immutable, self-contained operational time anchor.
 *
 * `proof` is a binary `SignedState` protobuf containing the canonical
 * anchor payload and HMAC signature. This keeps runtime metadata compact
 * while preserving deterministic verification semantics.
 */
struct TimeAnchor {
    uint64_t    logical_time = 0;
    int64_t     drift_us = 0;
    uint64_t    uncertainty_s = 0;
    std::string proof;
    std::string authority;
    std::string event_id;
    bool        is_valid = false;

    // Runtime gossip telemetry only.
    bool        gossip_validated = false;
    uint32_t    gossip_hops = 0;
};

/**
 * @brief In-process BFT time adapter.
 *
 * Runtime role split:
 * - `verify()` performs Live Operational Validation for immediate fail-closed gating.
 * - Historical forensic audit/reconstruction remains the authority of Aegis Lens.
 */
class QuorumTimeAdapter {
public:
    struct Config {
        std::filesystem::path data_dir = "./data/quorum_adapter";
        std::string hmac_key;
        std::string key_id = "v1";

        std::vector<NtpServerEntry> ntp_servers = {
            { "time.cloudflare.com", 1000, 2000 },
            { "time.google.com", 1000, 2000 },
            { "time.nist.gov", 1000, 2000 }
        };

        uint32_t min_quorum = 3;
        int64_t max_total_drift = 3600;
        int64_t max_drift_step = 60;
        int64_t max_cluster_skew = 10;
        int sync_interval_s = 60;
        bool fail_before_sync = false;

        // Optional gossip egress integration.
        std::shared_ptr<IGossipProvider> gossip_provider;
    };

    explicit QuorumTimeAdapter(const Config& cfg);
    ~QuorumTimeAdapter();

    QuorumTimeAdapter(const QuorumTimeAdapter&) = delete;
    QuorumTimeAdapter& operator=(const QuorumTimeAdapter&) = delete;
    QuorumTimeAdapter(QuorumTimeAdapter&&) = delete;
    QuorumTimeAdapter& operator=(QuorumTimeAdapter&&) = delete;

    void start();
    void stop();
    bool is_running() const noexcept;

    TimeAnchor now() const;

    TimeAnchor anchor_event(const std::string& event_id,
                            const std::string& event_hash) const;

    /**
     * @brief Live Operational Validation for runtime fail-closed decisions.
     *
     * Verifies:
     * - binary proof integrity/signature under current key_id/hmac_key
     * - anchor field consistency
     * - operational sanity against local BFT clock view
     * - optional event binding (supports Merkle-root batch anchors)
     */
    bool verify(const TimeAnchor& anchor,
                std::string_view event_hash = {}) const;

    uint64_t sync_count() const noexcept;
    uint64_t error_count() const noexcept;
    int64_t current_drift_us() const noexcept;

private:
    static bool is_probable_merkle_root(std::string_view event_hash);
    static std::string normalize_root(std::string_view event_hash);

    void fill_anchor_proof(uint64_t agreed_time,
                           const std::string& observation_hash,
                           size_t quorum_size,
                           const std::string& authority_set,
                           const std::string& event_id,
                           std::string_view event_hash,
                           AnchorProof* out) const;

    std::string build_proof(uint64_t agreed_time,
                            const std::string& observation_hash,
                            size_t quorum_size,
                            const std::string& authority_set,
                            const std::string& event_id,
                            std::string_view event_hash) const;

    void sync_loop();

private:
    Config cfg_;

    OsStrongClock os_clock_;
    SimpleHashProvider hash_provider_;
    std::shared_ptr<SimpleFileVaultBackend> vault_backend_;
    std::shared_ptr<ColdVault> vault_;
    std::shared_ptr<BFTQuorumTrustedClock> clock_;
    std::shared_ptr<NtpObservationFetcher> fetcher_;
    std::shared_ptr<IGossipProvider> gossip_provider_;
    ClockGovernor governor_;
    std::unique_ptr<EventOrchestrator> orchestrator_;
    PipelineBootstrapRuntime pipeline_runtime_;

    std::thread sync_thread_;
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> running_{false};

    mutable std::atomic<uint64_t> sync_count_{0};
    mutable std::atomic<uint64_t> error_count_{0};
};

} // namespace uml001
