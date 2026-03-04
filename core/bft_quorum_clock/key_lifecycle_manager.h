// key_lifecycle_manager.h
#pragma once

#include "crypto_utils.h"   // ed25519_keygen(), ed25519_sign(), sha256_hex, etc.
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <fstream>
#include <nlohmann/json.hpp>

// Simple key states
enum class DaemonKeyState {
    ACTIVE,
    ROTATING,
    RETIRED
};

struct DaemonKeyMetadata {
    std::string   key_id;          // e.g. sha256(pubkey)
    std::string   pubkey_hex;      // 64 hex chars
    std::string   privkey_hex;     // 128 hex chars (or encrypted blob)
    DaemonKeyState state;
    uint64_t      created_at;      // unix seconds
    uint64_t      activated_at;    // unix seconds
    uint64_t      retired_at;      // unix seconds (0 if not retired)
};

struct KeyRotationConfig {
    uint64_t overlap_window_s = 3600;   // old key still accepted for this long
    uint64_t max_key_age_s    = 30ULL * 24 * 3600; // 30 days
    bool     fail_closed      = true;   // abort if no valid key
};

// JSON helpers
inline void to_json(nlohmann::json& j, const DaemonKeyMetadata& m) {
    j = nlohmann::json{
        {"key_id",        m.key_id},
        {"pubkey_hex",    m.pubkey_hex},
        {"privkey_hex",   m.privkey_hex},
        {"state",         static_cast<int>(m.state)},
        {"created_at",    m.created_at},
        {"activated_at",  m.activated_at},
        {"retired_at",    m.retired_at}
    };
}

inline void from_json(const nlohmann::json& j, DaemonKeyMetadata& m) {
    int st;
    j.at("key_id").get_to(m.key_id);
    j.at("pubkey_hex").get_to(m.pubkey_hex);
    j.at("privkey_hex").get_to(m.privkey_hex);
    j.at("state").get_to(st);
    m.state = static_cast<DaemonKeyState>(st);
    j.at("created_at").get_to(m.created_at);
    j.at("activated_at").get_to(m.activated_at);
    j.at("retired_at").get_to(m.retired_at);
}

// -----------------------------------------------------------------------------
// DaemonKeyManager
// -----------------------------------------------------------------------------
//
// Responsibilities:
//  - Load/save keyset from a JSON file (or other backing store).
//  - Maintain exactly one ACTIVE key at a time.
//  - Support rotation with overlap window (old key accepted for verification).
//  - Enforce max key age and fail-closed semantics.
//  - Provide signing with the ACTIVE key and verification against all non-purged keys.
//
class DaemonKeyManager {
public:
    DaemonKeyManager(std::string path,
                     KeyRotationConfig cfg,
                     std::function<uint64_t()> now_fn)
        : path_(std::move(path)), cfg_(cfg), now_fn_(std::move(now_fn)) {
        load();
        ensure_active_key();
    }

    // Returns the current ACTIVE public key (for pinning in clients).
    std::string active_pubkey_hex() const {
        std::lock_guard<std::mutex> lock(mu_);
        const auto* k = find_active_key();
        if (!k) throw std::runtime_error("no ACTIVE key");
        return k->pubkey_hex;
    }

    // Sign payload with ACTIVE key.
    std::string sign(const std::string& payload) const {
        std::lock_guard<std::mutex> lock(mu_);
        const auto* k = find_active_key();
        if (!k) throw std::runtime_error("no ACTIVE key for signing");
        return ed25519_sign(payload, k->privkey_hex);
    }

    // Verify against any non-retired key (ACTIVE or ROTATING).
    bool verify(const std::string& payload,
                const std::string& signature,
                const std::string& pubkey_hex) const {
        // You may already have a crypto_verify() that takes pubkey.
        return crypto_verify_with_pubkey(payload, signature, pubkey_hex);
    }

    // Verify using any known key by key_id (for responses that carry key_id).
    bool verify_by_key_id(const std::string& payload,
                          const std::string& signature,
                          const std::string& key_id) const {
        std::lock_guard<std::mutex> lock(mu_);
        const DaemonKeyMetadata* k = find_key_by_id(key_id);
        if (!k) return false;
        if (k->state == DaemonKeyState::RETIRED) return false;
        return crypto_verify_with_pubkey(payload, signature, k->pubkey_hex);
    }

    // Rotate: create a new key, mark old ACTIVE as ROTATING, new as ACTIVE.
    // Old key remains valid for verification until overlap window expires.
    void rotate() {
        std::lock_guard<std::mutex> lock(mu_);
        uint64_t now = now_fn_();

        // Mark current ACTIVE as ROTATING
        DaemonKeyMetadata* active = find_active_key();
        if (active) {
            active->state = DaemonKeyState::ROTATING;
            active->retired_at = now + cfg_.overlap_window_s;
        }

        // Generate new keypair
        auto [pub_hex, priv_hex] = ed25519_keygen();
        DaemonKeyMetadata m;
        m.pubkey_hex   = pub_hex;
        m.privkey_hex  = priv_hex;
        m.key_id       = sha256_hex(pub_hex);
        m.state        = DaemonKeyState::ACTIVE;
        m.created_at   = now;
        m.activated_at = now;
        m.retired_at   = 0;

        keys_.push_back(std::move(m));
        save();
    }

    // Called periodically (e.g. on startup and on a timer) to:
    //  - Retire keys whose overlap window has passed.
    //  - Enforce max key age.
    //  - Ensure at least one ACTIVE key exists.
    void maintenance() {
        std::lock_guard<std::mutex> lock(mu_);
        uint64_t now = now_fn_();

        for (auto& k : keys_) {
            if (k.state == DaemonKeyState::ROTATING &&
                k.retired_at > 0 &&
                now >= k.retired_at) {
                k.state = DaemonKeyState::RETIRED;
            }

            if (k.state != DaemonKeyState::RETIRED &&
                (now - k.activated_at) > cfg_.max_key_age_s) {
                k.state      = DaemonKeyState::RETIRED;
                k.retired_at = now;
            }
        }

        purge_retired();
        ensure_active_key();
        save();
    }

private:
    std::string                    path_;
    KeyRotationConfig              cfg_;
    std::function<uint64_t()>      now_fn_;
    mutable std::mutex             mu_;
    std::vector<DaemonKeyMetadata> keys_;

    void load() {
        std::lock_guard<std::mutex> lock(mu_);
        std::ifstream f(path_);
        if (!f.is_open()) {
            // First run: no file yet. We'll create one on save().
            return;
        }
        nlohmann::json j;
        f >> j;
        keys_.clear();
        for (const auto& item : j) {
            DaemonKeyMetadata m;
            from_json(item, m);
            keys_.push_back(std::move(m));
        }
    }

    void save() const {
        std::lock_guard<std::mutex> lock(mu_);
        nlohmann::json j = nlohmann::json::array();
        for (const auto& k : keys_) {
            j.push_back(k);
        }
        std::ofstream f(path_, std::ios::trunc);
        if (!f.is_open()) {
            throw std::runtime_error("cannot open key file for write: " + path_);
        }
        f << j.dump(2);
    }

    DaemonKeyMetadata* find_active_key() {
        for (auto& k : keys_) {
            if (k.state == DaemonKeyState::ACTIVE) return &k;
        }
        return nullptr;
    }

    const DaemonKeyMetadata* find_active_key() const {
        for (const auto& k : keys_) {
            if (k.state == DaemonKeyState::ACTIVE) return &k;
        }
        return nullptr;
    }

    DaemonKeyMetadata* find_key_by_id(const std::string& id) {
        for (auto& k : keys_) {
            if (k.key_id == id) return &k;
        }
        return nullptr;
    }

    void purge_retired() {
        // Optional: keep retired keys for forensics; here we drop them.
        keys_.erase(
            std::remove_if(keys_.begin(), keys_.end(),
                           [](const DaemonKeyMetadata& k) {
                               return k.state == DaemonKeyState::RETIRED;
                           }),
            keys_.end());
    }

    void ensure_active_key() {
        uint64_t now = now_fn_();
        if (find_active_key()) return;

        // No ACTIVE key: either first run or all retired.
        if (keys_.empty()) {
            auto [pub_hex, priv_hex] = ed25519_keygen();
            DaemonKeyMetadata m;
            m.pubkey_hex   = pub_hex;
            m.privkey_hex  = priv_hex;
            m.key_id       = sha256_hex(pub_hex);
            m.state        = DaemonKeyState::ACTIVE;
            m.created_at   = now;
            m.activated_at = now;
            m.retired_at   = 0;
            keys_.push_back(std::move(m));
            save();
            return;
        }

        if (cfg_.fail_closed) {
            throw std::runtime_error("no ACTIVE key and fail_closed=true");
        } else {
            // Promote the newest non-retired key to ACTIVE as a last resort.
            DaemonKeyMetadata* newest = nullptr;
            for (auto& k : keys_) {
                if (k.state == DaemonKeyState::RETIRED) continue;
                if (!newest || k.activated_at > newest->activated_at) {
                    newest = &k;
                }
            }
            if (!newest) {
                auto [pub_hex, priv_hex] = ed25519_keygen();
                DaemonKeyMetadata m;
                m.pubkey_hex   = pub_hex;
                m.privkey_hex  = priv_hex;
                m.key_id       = sha256_hex(pub_hex);
                m.state        = DaemonKeyState::ACTIVE;
                m.created_at   = now;
                m.activated_at = now;
                m.retired_at   = 0;
                keys_.push_back(std::move(m));
            } else {
                newest->state = DaemonKeyState::ACTIVE;
            }
            save();
        }
    }
};
