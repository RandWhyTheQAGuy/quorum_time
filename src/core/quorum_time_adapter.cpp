/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 */

#include "uml001/quorum_time_adapter.h"

#include "proto/signed_state.pb.h"
#include "uml001/gossip_interface.h"
#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"
#include "uml001/vault_logger.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace uml001 {

namespace fs = std::filesystem;

namespace {

bool is_hex_64(std::string_view s)
{
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

std::string lower_copy(std::string_view s)
{
    std::string out(s);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

} // namespace

QuorumTimeAdapter::QuorumTimeAdapter(const Config& cfg)
    : cfg_(cfg),
      gossip_provider_(cfg.gossip_provider),
      governor_(cfg.min_quorum)
{
    if (cfg_.hmac_key.empty()) {
        throw std::invalid_argument(
            "QuorumTimeAdapter: hmac_key must not be empty. "
            "Generate one with uml001::generate_random_bytes_hex(32).");
    }

    try {
        fs::create_directories(cfg_.data_dir);
    } catch (const std::exception& e) {
        throw std::runtime_error(
            std::string("QuorumTimeAdapter: failed to create data_dir '") +
            cfg_.data_dir.string() + "': " + e.what());
    }

    for (const auto& server : cfg_.ntp_servers) {
        register_hmac_authority(server.hostname, cfg_.key_id, cfg_.hmac_key);
    }

    std::unordered_set<std::string> authorities;
    for (const auto& server : cfg_.ntp_servers) {
        authorities.insert(server.hostname);
    }

    ColdVault::Config vault_cfg;
    vault_cfg.base_directory = cfg_.data_dir;

    vault_backend_ = std::make_shared<SimpleFileVaultBackend>(
        cfg_.data_dir / "vault.log");

    vault_ = std::make_shared<ColdVault>(
        vault_cfg, vault_backend_, os_clock_, hash_provider_);

    set_vault_logger([this](const std::string& key, const std::string& val) {
        vault_->log_security_event(key, val);
    });

    BftClockConfig bft_cfg;
    bft_cfg.min_quorum       = cfg_.min_quorum;
    bft_cfg.max_total_drift  = cfg_.max_total_drift;
    bft_cfg.max_drift_step   = cfg_.max_drift_step;
    bft_cfg.max_cluster_skew = cfg_.max_cluster_skew;
    bft_cfg.fail_closed      = true;

    clock_ = std::make_shared<BFTQuorumTrustedClock>(
        bft_cfg, authorities, vault_);

    fetcher_ = std::make_shared<NtpObservationFetcher>(
        cfg_.hmac_key,
        cfg_.key_id,
        cfg_.ntp_servers,
        static_cast<std::size_t>(cfg_.min_quorum),
        1000,
        2000);

    orchestrator_ = std::make_unique<EventOrchestrator>(clock_.get(), vault_.get());
    pipeline_runtime_ = register_default_pipeline(
        *orchestrator_,
        *vault_,
        *clock_,
        governor_,
        hash_provider_,
        nullptr,
        "adapter-local");
}

QuorumTimeAdapter::~QuorumTimeAdapter()
{
    stop();
}

void QuorumTimeAdapter::start()
{
    if (running_.load(std::memory_order_acquire)) return;

    shutdown_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);

    sync_thread_ = std::thread([this]() { sync_loop(); });
}

void QuorumTimeAdapter::stop()
{
    if (!running_.load(std::memory_order_acquire)) return;

    shutdown_.store(true, std::memory_order_release);

    if (sync_thread_.joinable()) {
        sync_thread_.join();
    }

    running_.store(false, std::memory_order_release);
}

bool QuorumTimeAdapter::is_running() const noexcept
{
    return running_.load(std::memory_order_acquire);
}

TimeAnchor QuorumTimeAdapter::now() const
{
    TimeAnchor anchor;

    if (cfg_.fail_before_sync &&
        sync_count_.load(std::memory_order_acquire) == 0) {
        anchor.is_valid = false;
        return anchor;
    }

    const uint64_t agreed_time = clock_->now_unix();
    const int64_t drift = clock_->get_current_drift();
    const uint64_t uncertainty = clock_->get_current_uncertainty();

    const std::string obs_hash = sha256_hex(std::to_string(agreed_time));

    anchor.logical_time  = agreed_time;
    anchor.drift_us      = drift;
    anchor.uncertainty_s = uncertainty;
    anchor.is_valid      = (agreed_time > 0);

    anchor.gossip_validated =
        gossip_provider_ ? gossip_provider_->is_external() : false;
    anchor.gossip_hops = 0;

    anchor.proof = build_proof(
        agreed_time, obs_hash, 0, "", "", std::string_view());

    return anchor;
}

TimeAnchor QuorumTimeAdapter::anchor_event(
    const std::string& event_id,
    const std::string& event_hash) const
{
    TimeAnchor anchor = now();
    if (!anchor.is_valid) return anchor;

    anchor.event_id = event_id;

    const std::string obs_hash =
        sha256_hex(std::to_string(anchor.logical_time));

    anchor.proof = build_proof(
        anchor.logical_time,
        obs_hash,
        0,
        "",
        event_id,
        event_hash);

    if (gossip_provider_) {
        SignedState state;
        state.set_logical_time_ns(anchor.logical_time * 1000000000ULL);
        state.set_event_id(event_id);
        state.set_key_id(cfg_.key_id);

        auto* g = state.mutable_gossip();
        g->set_hops(0);
        g->set_ttl(6);
        g->set_validated(gossip_provider_->is_external());

        gossip_provider_->broadcast(state);
    }

    return anchor;
}

bool QuorumTimeAdapter::is_probable_merkle_root(std::string_view event_hash)
{
    if (event_hash.empty()) return false;
    if (event_hash.rfind("mr:", 0) == 0) return true;
    if (event_hash.rfind("merkle:", 0) == 0) return true;
    return is_hex_64(event_hash);
}

std::string QuorumTimeAdapter::normalize_root(std::string_view event_hash)
{
    if (event_hash.rfind("mr:", 0) == 0) {
        return lower_copy(event_hash.substr(3));
    }
    if (event_hash.rfind("merkle:", 0) == 0) {
        return lower_copy(event_hash.substr(7));
    }
    return lower_copy(event_hash);
}

void QuorumTimeAdapter::fill_anchor_proof(
    uint64_t agreed_time,
    const std::string& observation_hash,
    size_t quorum_size,
    const std::string& authority_set,
    const std::string& event_id,
    std::string_view event_hash,
    AnchorProof* out) const
{
    (void)agreed_time;
    if (!out) return;

    const bool merkle_root = is_probable_merkle_root(event_hash);
    out->set_version(1);
    out->set_is_merkle_root(merkle_root);
    out->set_observation_hash(observation_hash);
    out->set_quorum_size(static_cast<uint32_t>(quorum_size));
    out->set_authority_set(authority_set);
    out->set_event_id(event_id);
    out->set_event_hash(merkle_root ? normalize_root(event_hash)
                                    : std::string(event_hash));
}

std::string QuorumTimeAdapter::build_proof(
    uint64_t agreed_time,
    const std::string& observation_hash,
    size_t quorum_size,
    const std::string& authority_set,
    const std::string& event_id,
    std::string_view event_hash) const
{
    SignedState proof_msg;
    proof_msg.set_logical_time_ns(agreed_time * 1000000000ULL);
    proof_msg.set_event_id(event_id.empty() ? "time.anchor" : event_id);
    proof_msg.set_key_id(cfg_.key_id);
    fill_anchor_proof(
        agreed_time,
        observation_hash,
        quorum_size,
        authority_set,
        event_id,
        event_hash,
        proof_msg.mutable_anchor_proof());

    std::string canonical;
    if (!proof_msg.SerializeToString(&canonical)) {
        throw std::runtime_error("QuorumTimeAdapter: failed to serialize canonical proof");
    }

    proof_msg.set_signature(hmac_sha256_hex(cfg_.hmac_key, canonical));

    std::string encoded;
    if (!proof_msg.SerializeToString(&encoded)) {
        throw std::runtime_error("QuorumTimeAdapter: failed to serialize signed proof");
    }

    return encoded;
}

bool QuorumTimeAdapter::verify(
    const TimeAnchor& anchor,
    std::string_view event_hash) const
{
    if (!anchor.is_valid || anchor.logical_time == 0 || anchor.proof.empty()) {
        return false;
    }

    SignedState proof_msg;
    if (!proof_msg.ParseFromString(anchor.proof)) {
        return false;
    }

    // Key binding protection across rotation windows.
    if (proof_msg.key_id() != cfg_.key_id || anchor.event_id != "" && proof_msg.event_id() != anchor.event_id) {
        return false;
    }

    const uint64_t proof_time = proof_msg.logical_time_ns() / 1000000000ULL;
    if (proof_time != anchor.logical_time) {
        return false;
    }

    std::string signature_hex = proof_msg.signature();
    proof_msg.clear_signature();

    std::string canonical;
    if (!proof_msg.SerializeToString(&canonical)) {
        return false;
    }

    const std::string expected_sig = hmac_sha256_hex(cfg_.hmac_key, canonical);
    if (expected_sig != signature_hex) {
        return false;
    }

    if (!proof_msg.has_anchor_proof()) {
        return false;
    }

    const AnchorProof& ap = proof_msg.anchor_proof();
    if (ap.version() != 1) {
        return false;
    }

    const std::string& observation_hash = ap.observation_hash();
    const std::string& authority_set = ap.authority_set();
    const std::string& proof_event_id = ap.event_id();
    const std::string& proof_event_hash = ap.event_hash();
    const bool proof_merkle_root = ap.is_merkle_root();

    size_t quorum_size = static_cast<size_t>(ap.quorum_size());
    (void)quorum_size;

    const std::string expected_obs_hash = sha256_hex(std::to_string(anchor.logical_time));
    if (observation_hash != expected_obs_hash) {
        return false;
    }

    if (!anchor.authority.empty() && anchor.authority != authority_set) {
        return false;
    }

    if (!event_hash.empty()) {
        if (proof_merkle_root || is_probable_merkle_root(event_hash)) {
            if (normalize_root(event_hash) != normalize_root(proof_event_hash)) {
                return false;
            }
        } else {
            if (std::string(event_hash) != proof_event_hash) {
                return false;
            }
        }
    }

    // Read-only operational sanity check against local BFT clock view.
    const uint64_t now = clock_->now_unix();
    const uint64_t uncertainty = clock_->get_current_uncertainty();
    if (now > 0 && uncertainty != 0xFFFFFFFF) {
        if (anchor.logical_time > now + uncertainty + 1) {
            return false;
        }
    }

    return true;
}

void QuorumTimeAdapter::sync_loop()
{
    std::this_thread::sleep_for(std::chrono::seconds(1));

    while (!shutdown_.load(std::memory_order_acquire)) {
        const auto tick_start = std::chrono::steady_clock::now();

        try {
            auto observations = fetcher_->fetch();

            if (!observations.empty()) {
                std::string payload;
                pipeline::encode_ntp_sync_payload(observations, 0.0, &payload);

                SignedState event;
                event.set_event_id(pipeline::WORKER_NTP_SYNC);
                event.set_logical_time_ns(clock_->now_unix() * 1000000000ULL);
                event.set_payload(payload);
                event.mutable_gossip()->set_hops(1);

                const auto ctx = orchestrator_->ingest_with_context(event);
                if (ctx.quorum_updated && ctx.rest_sync_result.has_value()) {
                    sync_count_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    error_count_.fetch_add(1, std::memory_order_relaxed);
                    vault_->log_security_event(
                        "sync.quorum_rejected",
                        "pipeline did not commit; reason=" + ctx.audit_reason);
                }
            } else {
                error_count_.fetch_add(1, std::memory_order_relaxed);
                vault_->log_security_event(
                    "sync.no_observations",
                    "NTP fetch returned empty set");
            }
        } catch (const std::exception& e) {
            error_count_.fetch_add(1, std::memory_order_relaxed);
            vault_log("sync.exception", e.what());
        } catch (...) {
            error_count_.fetch_add(1, std::memory_order_relaxed);
            vault_log("sync.unknown_exception", "unknown error");
        }

        const auto elapsed = std::chrono::steady_clock::now() - tick_start;
        const auto target = std::chrono::seconds(cfg_.sync_interval_s);

        auto remaining = target - elapsed;

        while (remaining.count() > 0 &&
               !shutdown_.load(std::memory_order_acquire)) {

            const auto chunk = std::min(
                remaining,
                std::chrono::duration_cast<decltype(remaining)>(
                    std::chrono::milliseconds(500)));

            std::this_thread::sleep_for(chunk);
            remaining -= chunk;
        }
    }
}

uint64_t QuorumTimeAdapter::sync_count() const noexcept
{
    return sync_count_.load(std::memory_order_relaxed);
}

uint64_t QuorumTimeAdapter::error_count() const noexcept
{
    return error_count_.load(std::memory_order_relaxed);
}

int64_t QuorumTimeAdapter::current_drift_us() const noexcept
{
    return clock_->get_current_drift();
}

} // namespace uml001
