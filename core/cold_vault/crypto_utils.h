#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace uml001 {

// ===================== HASHING =====================

std::string sha256_hex(const std::string& data);
std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data);

// ===================== RANDOM =====================

std::vector<uint8_t> secure_random_bytes(size_t length);

// ===================== CONSTANT TIME =====================

bool constant_time_equals(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b);

// ===================== BASE64 =====================

std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& input);

// ===================== ED25519 =====================

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message);

bool ed25519_verify(const std::vector<uint8_t>& public_key,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature);

// ===================== AES-256-GCM =====================

struct AESGCMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> tag;
};

AESGCMResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& aad);

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad);

// ===================== SECURE ZERO =====================

void secure_zero(std::vector<uint8_t>& buffer);

} // namespace uml001