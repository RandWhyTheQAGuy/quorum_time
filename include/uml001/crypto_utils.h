#pragma once

/**
 * @file crypto_utils.h
 * @brief Cryptographic utilities for UML-001.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include "uml001/hash_provider.h"

namespace uml001 {

/**
 * @brief Result of AES-256-GCM encryption or decryption.
 *
 * NOTE: Field names MUST match crypto_utils.cpp.
 *       The implementation uses `result.nonce`, not `iv`.
 */
struct AESGCMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;   // ← REQUIRED NAME (crypto_utils.cpp uses this)
    std::vector<uint8_t> tag;
    bool ok = false;
};

/**
 * @brief Encrypt using AES-256-GCM.
 *
 * @param key        32-byte AES key
 * @param plaintext  bytes to encrypt
 * @return AESGCMResult containing ciphertext, nonce, tag, and ok flag
 */
AESGCMResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& plaintext);

/**
 * @brief Decrypt using AES-256-GCM.
 *
 * @param key         32-byte AES key
 * @param ciphertext  encrypted bytes
 * @param nonce       12-byte GCM nonce
 * @param tag         authentication tag
 * @return AESGCMResult with plaintext in ciphertext field if ok=true
 */
AESGCMResult aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& ciphertext,
                                const std::vector<uint8_t>& nonce,
                                const std::vector<uint8_t>& tag);

/**
 * @brief Register an HMAC authority and its key.
 */
void register_hmac_authority(const std::string& authority_id,
                             const std::string& key_id,
                             const std::string& hmac_key_hex);

/**
 * @brief Verify a signature using the appropriate crypto backend.
 */
bool crypto_verify(const std::string& payload,
                   const std::string& signature_hex,
                   const std::string& authority_id,
                   const std::string& key_id);

/**
 * @brief Generate random bytes and return them as hex.
 */
std::string generate_random_bytes_hex(std::size_t n);

/**
 * @brief Convenience helper: compute SHA-256 and return lowercase hex.
 *
 * Uses the global/default hash provider.
 */
std::string sha256_hex(const std::string& input);

} // namespace uml001
