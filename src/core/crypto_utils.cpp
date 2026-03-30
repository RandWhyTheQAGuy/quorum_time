/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine‑resilient trusted‑time
 * system designed for modern distributed environments. It provides a
 * cryptographically anchored notion of time that can be aligned,
 * audited, and shared across domains without requiring centralized
 * trust.
 *
 * This project also includes the Aegis Semantic Passport components,
 * which complement Quorum Time by offering structured, verifiable
 * identity and capability attestations for agents and services.
 *
 * Core capabilities:
 *   - BFT Quorum Time: multi‑authority, tamper‑evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross‑domain alignment (AlignTime).
 *
 *   - Transparency Logging: append‑only, hash‑chained audit records
 *                           for time events, alignment proofs, and
 *                           key‑rotation operations.
 *
 *   - Semantic Passports: optional identity and capability metadata
 *                         for systems that require verifiable agent
 *                         provenance and authorization context.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security‑critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open‑source project with a focus on
 * clarity, auditability, and long‑term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community‑driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <mutex>
#include <unordered_map>

namespace uml001 {

static std::mutex g_hmac_mutex;
static std::unordered_map<std::string, std::vector<uint8_t>> g_hmac_keys;

static void throw_openssl_error(const std::string& msg) {
    unsigned long err = ERR_get_error();
    std::ostringstream oss;
    oss << msg << " | OpenSSL: " << (err ? ERR_error_string(err, nullptr) : "Unknown");
    throw std::runtime_error(oss.str());
}

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < hex.length(); i += 2) {
        out.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return out;
}

static bool try_hex_to_bytes(const std::string& hex, std::vector<uint8_t>* out)
{
    if (!out) return false;
    out->clear();
    if ((hex.size() % 2) != 0) return false;
    out->reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const unsigned char hi = static_cast<unsigned char>(hex[i]);
        const unsigned char lo = static_cast<unsigned char>(hex[i + 1]);
        if (!std::isxdigit(hi) || !std::isxdigit(lo)) {
            out->clear();
            return false;
        }
        try {
            out->push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        } catch (...) {
            out->clear();
            return false;
        }
    }
    return true;
}

// 1. Implementation for sha256_hex
std::string sha256_hex(const std::string& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    std::vector<uint8_t> hash(EVP_MD_get_size(md));
    unsigned int length = 0;
    
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &length);
    EVP_MD_CTX_free(ctx);
    
    hash.resize(length);
    return bytes_to_hex(hash);
}

// 2. Implementation for hmac_sha256_hex
std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    size_t mac_len = 0;
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);
    EVP_MAC* mac_obj = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac_obj);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MAC_init(ctx, (const unsigned char*)key.data(), key.size(), params);
    EVP_MAC_update(ctx, (const unsigned char*)data.data(), data.size());
    EVP_MAC_final(ctx, mac.data(), &mac_len, mac.size());

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_obj);
    
    mac.resize(mac_len);
    return bytes_to_hex(mac);
}

// 3. Implementation for generate_random_bytes_hex
std::string generate_random_bytes_hex(unsigned long length) {
    // Re-use your existing secure_random_bytes function
    std::vector<uint8_t> buf = secure_random_bytes(length);
    return bytes_to_hex(buf);
}

void register_hmac_authority(const std::string& authority_id, const std::string& key_id, const std::string& key_hex) {
    std::lock_guard<std::mutex> lock(g_hmac_mutex);
    g_hmac_keys[authority_id + "|" + key_id] = hex_to_bytes(key_hex);
}

/**
 * Modern OpenSSL 3.0 EVP_MAC Implementation (FIPS compliant)
 */
bool crypto_verify(const std::string& payload, const std::string& signature_hex,
                   const std::string& authority_id, const std::string& key_id) {
    std::vector<uint8_t> key;
    {
        std::lock_guard<std::mutex> lock(g_hmac_mutex);
        auto it = g_hmac_keys.find(authority_id + "|" + key_id);
        if (it == g_hmac_keys.end()) return false;
        key = it->second;
    }

    size_t mac_len = 0;
    std::vector<uint8_t> mac(32);
    EVP_MAC* mac_obj = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac_obj);
    
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!ctx || EVP_MAC_init(ctx, key.data(), key.size(), params) != 1) {
        if (ctx) EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_obj);
        return false;
    }

    EVP_MAC_update(ctx, (const unsigned char*)payload.data(), payload.size());
    EVP_MAC_final(ctx, mac.data(), &mac_len, mac.size());

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_obj);

    std::vector<uint8_t> sig_bytes;
    if (!try_hex_to_bytes(signature_hex, &sig_bytes)) {
        return false;
    }
    return (mac_len == sig_bytes.size() && CRYPTO_memcmp(mac.data(), sig_bytes.data(), mac_len) == 0);
}

std::vector<uint8_t> secure_random_bytes(size_t length) {
    std::vector<uint8_t> buf(length);
    if (RAND_bytes(buf.data(), (int)length) != 1) throw_openssl_error("RAND_bytes failed");
    return buf;
}

} // namespace uml001