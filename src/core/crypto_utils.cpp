#include "uml001/crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <cstdint>
#include "uml001/simple_hash_provider.h"

// Global fallback hash provider (simple software hash)
static uml001::SimpleHashProvider g_default_hash_provider;

namespace uml001 {

std::string sha256_hex(const std::string& input) {
    return g_default_hash_provider.sha256(input);
}

} // namespace uml001

namespace uml001 {

// ===================== INTERNAL HELPERS =====================

static void throw_openssl_error(const std::string& msg) {
    unsigned long err = ERR_get_error();
    std::ostringstream oss;
    oss << msg;
    if (err)
        oss << " | OpenSSL: " << ERR_error_string(err, nullptr);
    throw std::runtime_error(oss.str());
}

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0)
        throw std::runtime_error("hex_to_bytes: odd-length hex string");

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned int value = 0;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> value;
        if (!iss)
            throw std::runtime_error("hex_to_bytes: invalid hex digit");
        out.push_back(static_cast<uint8_t>(value));
    }
    return out;
}

// ===================== SHA256 =====================

std::vector<uint8_t> sha256_raw(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        throw_openssl_error("DigestInit failed");

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
        throw_openssl_error("DigestUpdate failed");

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &len) != 1)
        throw_openssl_error("DigestFinal failed");

    EVP_MD_CTX_free(ctx);
    return digest;
}

// ===================== RANDOM =====================

std::vector<uint8_t> secure_random_bytes(size_t length) {
    std::vector<uint8_t> buf(length);
    if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1)
        throw_openssl_error("RAND_bytes failed");
    return buf;
}

std::string generate_random_bytes_hex(std::size_t num_bytes) {
    auto bytes = secure_random_bytes(num_bytes);
    return bytes_to_hex(bytes);
}

// ===================== CONSTANT TIME =====================

bool constant_time_equals(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b)
{
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ===================== BASE64 =====================

std::string base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), static_cast<int>(input.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<uint8_t> buffer(input.size());
    int decoded_len = BIO_read(bio, buffer.data(), static_cast<int>(buffer.size()));
    BIO_free_all(bio);

    if (decoded_len < 0)
        throw std::runtime_error("Base64 decode failed");

    buffer.resize(static_cast<std::size_t>(decoded_len));
    return buffer;
}

// ===================== ED25519 =====================

std::vector<uint8_t> ed25519_sign(const std::vector<uint8_t>& private_key,
                                  const std::vector<uint8_t>& message)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        private_key.data(), private_key.size());

    if (!pkey) throw_openssl_error("ED25519 private key init failed");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1)
        throw_openssl_error("ED25519 DigestSignInit failed");

    size_t sig_len = 64;
    std::vector<uint8_t> signature(sig_len);

    if (EVP_DigestSign(ctx, signature.data(), &sig_len,
                       message.data(), message.size()) != 1)
        throw_openssl_error("ED25519 sign failed");

    signature.resize(sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return signature;
}

bool ed25519_verify(const std::vector<uint8_t>& public_key,
                    const std::vector<uint8_t>& message,
                    const std::vector<uint8_t>& signature)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        public_key.data(), public_key.size());

    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    int rc = EVP_DigestVerify(ctx,
                              signature.data(), signature.size(),
                              message.data(), message.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return rc == 1;
}

// ===================== AES-256-GCM =====================

AESGCMResult aes256_gcm_encrypt(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& plaintext,
                                const std::vector<uint8_t>& aad)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-256 requires 32-byte key");

    AESGCMResult result;
    result.nonce = secure_random_bytes(12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key.data(), result.nonce.data()) != 1)
        throw_openssl_error("AES-GCM EncryptInit failed");

    int len = 0;
    result.ciphertext.resize(plaintext.size());

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw_openssl_error("AES-GCM AAD update failed");
    }

    if (EVP_EncryptUpdate(ctx,
                          result.ciphertext.data(),
                          &len,
                          plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        throw_openssl_error("AES-GCM EncryptUpdate failed");

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1)
        throw_openssl_error("AES-GCM EncryptFinal failed");

    ciphertext_len += len;
    result.ciphertext.resize(static_cast<std::size_t>(ciphertext_len));

    result.tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            16, result.tag.data()) != 1)
        throw_openssl_error("AES-GCM GET_TAG failed");

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad)
{
    if (key.size() != 32)
        throw std::runtime_error("AES-256 requires 32-byte key");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key.data(), nonce.data()) != 1)
        throw_openssl_error("AES-GCM DecryptInit failed");

    int len = 0;
    std::vector<uint8_t> plaintext(ciphertext.size());

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1)
            throw_openssl_error("AES-GCM AAD update failed");
    }

    if (EVP_DecryptUpdate(ctx,
                          plaintext.data(),
                          &len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        throw_openssl_error("AES-GCM DecryptUpdate failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<uint8_t*>(tag.data())) != 1)
        throw_openssl_error("AES-GCM SET_TAG failed");

    if (EVP_DecryptFinal_ex(ctx,
                            plaintext.data() + len,
                            &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM authentication failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ===================== ZEROIZATION =====================

void secure_zero(std::vector<uint8_t>& buffer) {
    if (!buffer.empty()) {
        OPENSSL_cleanse(buffer.data(), buffer.size());
    }
}

// ===================== HMAC registry + verification =====================

namespace {
std::mutex g_hmac_mutex;
std::unordered_map<std::string, std::vector<uint8_t>> g_hmac_keys;
// key: authority_id + "|" + key_id  → raw 32-byte key
}

void register_hmac_authority(const std::string& authority_id,
                             const std::string& key_id,
                             const std::string& key_hex)
{
    const std::string map_key = authority_id + "|" + key_id;
    auto key_bytes = hex_to_bytes(key_hex);

    std::lock_guard<std::mutex> lock(g_hmac_mutex);
    g_hmac_keys[map_key] = std::move(key_bytes);
}

static std::string hmac_sha256_hex(const std::vector<uint8_t>& key,
                                   const std::string& payload)
{
    unsigned int len = 0;
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) throw std::runtime_error("HMAC_CTX_new failed");

    if (HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()),
                     EVP_sha256(), nullptr) != 1)
    {
        HMAC_CTX_free(ctx);
        throw_openssl_error("HMAC_Init_ex failed");
    }

    if (HMAC_Update(ctx,
                    reinterpret_cast<const unsigned char*>(payload.data()),
                    payload.size()) != 1)
    {
        HMAC_CTX_free(ctx);
        throw_openssl_error("HMAC_Update failed");
    }

    if (HMAC_Final(ctx, mac.data(), &len) != 1) {
        HMAC_CTX_free(ctx);
        throw_openssl_error("HMAC_Final failed");
    }

    HMAC_CTX_free(ctx);
    mac.resize(len);
    return bytes_to_hex(mac);
}

bool crypto_verify(const std::string& payload,
                   const std::string& signature_hex,
                   const std::string& authority_id,
                   const std::string& key_id)
{
    const std::string map_key = authority_id + "|" + key_id;

    std::vector<uint8_t> key;
    {
        std::lock_guard<std::mutex> lock(g_hmac_mutex);
        auto it = g_hmac_keys.find(map_key);
        if (it == g_hmac_keys.end()) {
            return false;
        }
        key = it->second;
    }

    const std::string computed = hmac_sha256_hex(key, payload);
    // constant-time compare on bytes
    std::vector<uint8_t> sig_bytes = hex_to_bytes(signature_hex);
    std::vector<uint8_t> cmp_bytes = hex_to_bytes(computed);
    return constant_time_equals(sig_bytes, cmp_bytes);
}

// ===================== TPM hooks (stubs) =====================

std::vector<uint8_t> tpm_ed25519_sign(const std::string& /*key_handle*/,
                                      const std::vector<uint8_t>& /*message*/)
{
    throw std::runtime_error("tpm_ed25519_sign not implemented");
}

bool tpm_ed25519_verify(const std::string& /*key_handle*/,
                        const std::vector<uint8_t>& /*message*/,
                        const std::vector<uint8_t>& /*signature*/)
{
    throw std::runtime_error("tpm_ed25519_verify not implemented");
}

} // namespace uml001