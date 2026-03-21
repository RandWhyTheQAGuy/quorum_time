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