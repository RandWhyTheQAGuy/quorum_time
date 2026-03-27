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
#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace uml001 {

struct AESGCMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> nonce;
};

/**
 * @brief Returns a hex-encoded SHA-256 hash of the input string.
 */
std::string sha256_hex(const std::string& input);

/**
 * @brief Computes HMAC-SHA256 of `message` under `key` and returns
 *        the result as a lowercase hex string.
 *        Used for signing/verifying SignedSharedClockState payloads
 *        and NTP observation authentication.
 */
std::string hmac_sha256_hex(const std::string& key, const std::string& message);

/**
 * @brief Generates `byte_count` cryptographically secure random bytes
 *        and returns them as a lowercase hex string (length = 2 * byte_count).
 *        Used for key generation in KeyRotationManager.
 */
std::string generate_random_bytes_hex(size_t byte_count);

/**
 * @brief Registers an HMAC key with the named authority (NTP server hostname).
 *        Subsequent observations from that authority will be verified with
 *        the given key_id / key_hex pair.
 * @param authority_id  NTP server hostname, e.g. "time.cloudflare.com"
 * @param key_id        Opaque version string, e.g. "v1"
 * @param key_hex       Hex-encoded 32-byte key produced by generate_random_bytes_hex
 */
void register_hmac_authority(const std::string& authority_id,
                              const std::string& key_id,
                              const std::string& key_hex);

/**
 * @brief Verifies a signature using the registered key for the given authority.
 */
bool crypto_verify(const std::string& payload,
                   const std::string& signature_hex,
                   const std::string& authority_id,
                   const std::string& key_id);

/**
 * @brief Generates cryptographically secure random bytes (raw bytes variant).
 */
std::vector<uint8_t> secure_random_bytes(size_t length);

} // namespace uml001