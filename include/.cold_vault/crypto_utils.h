#pragma once

/**
 * @file crypto_utils.h
 * @brief Cryptographic primitives and helpers for UML-001.
 *
 * DESIGN NOTES
 * ------------
 * - All operations are designed for use in security-critical paths:
 *   ColdVault, BFTQuorumTrustedClock, REST auth, and shared-state adoption.
 * - Ed25519 APIs are vector-based to avoid accidental string misuse.
 * - secure_zero() is provided to reduce key/secret lifetime in memory.
 * - Optional TPM hooks can be wired to hardware-backed keys without
 *   changing the high-level call sites.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace uml001 {

// ===================== SHA-256 =====================

/**
 * @brief Compute SHA-256 over arbitrary binary data.
 *
 * @param data Input bytes.
 * @return 32-byte SHA-256 digest.
 */
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data);

/**
 * @brief Compute SHA-256 over a string and return hex-encoded digest.
 *
 * @param data Input string (treated as raw bytes).
 * @return Hex-encoded SHA-256 digest (lowercase).
 */
std::string sha256_hex(const std::string& data);

// ===================== Secure random =====================

/**
 * @brief Generate cryptographically secure random bytes.
 *
 * @param length Number of bytes to generate.
 * @return Vector of random bytes.
 *
 * SECURITY:
 * - Must use a CSPRNG (e.g., OS-provided RNG).
 * - Suitable for keys, nonces, and salts.
 */
std::vector<uint8_t> secure_random_bytes(size_t length);

// ===================== Constant-time comparison =====================

/**
 * @brief Compare two byte vectors in constant time.
 *
 * @param a First vector.
 * @param b Second vector.
 * @return true if equal, false otherwise.
 *
 * SECURITY:
 * - Execution time does not depend on the contents of the buffers.
 * - Use for comparing MACs, tags, and signatures.
 */
bool constant_time_equals(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b);

// ===================== Base64 =====================

/**
 * @brief Base64-encode binary data.
 *
 * @param data Input bytes.
 * @return Base64-encoded string (no line breaks).
 */
std::string base64_encode(const std::vector<uint8_t>& data);

/**
 * @brief Base64-decode a string.
 *
 * @param input Base64-encoded string.
 * @return Decoded bytes. Throws or returns empty on invalid input
 *         depending on implementation choice.
 */
std::vector<uint8_t> base64_decode(const std::string& input);

// ===================== AES-256-GCM =====================

/**
 * @brief Result of AES-256-GCM encryption.
 *
 * - ciphertext: Encrypted payload.
 * - nonce:      Unique nonce/IV used for this encryption.
 * - tag:        Authentication tag (typically 16 bytes).
 */
struct AESGCMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
};

/**
 * @brief Encrypt data using AES-256-GCM.
 *
 * @param key       32-byte AES key.
 * @param plaintext Plaintext bytes.
 * @param aad       Additional authenticated data (not encrypted).
 * @return AESGCMResult containing ciphertext, nonce, and tag.
 *
 * SECURITY:
 * - Nonce must be unique per (key, nonce) pair.
 * - Implementation should generate a fresh random nonce internally.
 */
AESGCMResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& aad);

/**
 * @brief Decrypt data using AES-256-GCM.
 *
 * @param key        32-byte AES key.
 * @param ciphertext Ciphertext bytes.
 * @param nonce      Nonce used during encryption.
 * @param tag        Authentication tag.
 * @param aad        Additional authenticated data (must match encrypt).
 * @return Decrypted plaintext bytes. Implementation should signal failure
 *         (e.g., via empty vector or exception) if authentication fails.
 */
std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad);

// ===================== Zeroization =====================

/**
 * @brief Overwrite the contents of a buffer to reduce secret lifetime.
 *
 * @param buffer Buffer to zeroize.
 *
 * SECURITY:
 * - Intended for keys, nonces, and other sensitive material.
 * - Implementation should avoid being optimized away.
 */
void secure_zero(std::vector<uint8_t>& buffer);

// ===================== Ed25519 (vector-based) =====================

/**
 * @brief Sign a message using an Ed25519 private key.
 *
 * @param private_key Private key bytes (typically 32 or 64 bytes).
 * @param message     Message bytes to sign.
 * @return Signature bytes (64 bytes).
 */
std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message);

/**
 * @brief Verify an Ed25519 signature.
 *
 * @param public_key Public key bytes (32 bytes).
 * @param message    Message bytes that were signed.
 * @param signature  Signature bytes (64 bytes).
 * @return true if signature is valid, false otherwise.
 */
bool ed25519_verify(const std::vector<uint8_t>& public_key,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature);

// ===================== High-level verification hook =====================

/**
 * @brief Verify a hex-encoded signature over a canonical payload.
 *
 * @param payload       Canonical string payload (e.g., "leader|key|time|...").
 * @param signature_hex Hex-encoded signature.
 * @param authority_id  Logical authority identifier (e.g., NTP server name).
 * @param key_id        Key generation or slot identifier.
 * @return true if the signature is valid under the configured trust model.
 *
 * USAGE:
 * - BFTQuorumTrustedClock observation verification.
 * - Shared-state adoption from cluster leader.
 *
 * IMPLEMENTATION:
 * - Typically:
 *   1) Look up public key for (authority_id, key_id).
 *   2) Decode signature_hex to bytes.
 *   3) Verify using ed25519_verify().
 */
bool crypto_verify(const std::string& payload,
                   const std::string& signature_hex,
                   const std::string& authority_id,
                   const std::string& key_id);

// ===================== Optional TPM hooks =====================

/**
 * @brief Optional hook: sign using a TPM-backed Ed25519 key.
 *
 * @param key_handle   Logical handle or identifier for TPM-resident key.
 * @param message      Message bytes to sign.
 * @return Signature bytes (64 bytes).
 *
 * NOTE:
 * - This is a declaration only; implementation may be a no-op or throw
 *   if TPM support is not compiled in.
 */
std::vector<uint8_t> tpm_ed25519_sign(const std::string& key_handle,
                                      const std::vector<uint8_t>& message);

/**
 * @brief Optional hook: verify using a TPM-backed or TPM-attested key.
 *
 * @param key_handle Logical handle or identifier for TPM-resident key.
 * @param message    Message bytes that were signed.
 * @param signature  Signature bytes (64 bytes).
 * @return true if signature is valid, false otherwise.
 *
 * NOTE:
 * - Implementation may delegate to ed25519_verify() with a cached public key,
 *   or call into TPM verification primitives directly.
 */
bool tpm_ed25519_verify(const std::string& key_handle,
                        const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& signature);

} // namespace uml001
