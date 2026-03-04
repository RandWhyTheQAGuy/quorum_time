#include "crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace uml001 {

// ===================== INTERNAL HELPER =====================

static void throw_openssl_error(const std::string& msg) {
    unsigned long err = ERR_get_error();
    std::ostringstream oss;
    oss << msg;
    if (err)
        oss << " | OpenSSL: " << ERR_error_string(err, nullptr);
    throw std::runtime_error(oss.str());
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

std::string sha256_hex(const std::string& data) {
    std::vector<uint8_t> input(data.begin(), data.end());
    auto digest = sha256_raw(input);

    std::ostringstream oss;
    for (uint8_t byte : digest)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    return oss.str();
}

// ===================== RANDOM =====================

std::vector<uint8_t> secure_random_bytes(size_t length) {
    std::vector<uint8_t> buf(length);
    if (RAND_bytes(buf.data(), buf.size()) != 1)
        throw_openssl_error("RAND_bytes failed");
    return buf;
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

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> base64_decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), input.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    std::vector<uint8_t> buffer(input.size());
    int decoded_len = BIO_read(bio, buffer.data(), buffer.size());
    BIO_free_all(bio);

    if (decoded_len < 0)
        throw std::runtime_error("Base64 decode failed");

    buffer.resize(decoded_len);
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
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);

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
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);

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
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                       key.data(), result.nonce.data());

    int len;
    result.ciphertext.resize(plaintext.size());

    if (!aad.empty())
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    EVP_EncryptUpdate(ctx,
                      result.ciphertext.data(),
                      &len,
                      plaintext.data(),
                      plaintext.size());

    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len);
    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);

    result.tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                        16, result.tag.data());

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& tag,
                                        const std::vector<uint8_t>& aad)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                       key.data(), nonce.data());

    int len;
    std::vector<uint8_t> plaintext(ciphertext.size());

    if (!aad.empty())
        EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());

    EVP_DecryptUpdate(ctx,
                      plaintext.data(),
                      &len,
                      ciphertext.data(),
                      ciphertext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                        tag.size(), const_cast<uint8_t*>(tag.data()));

    if (EVP_DecryptFinal_ex(ctx,
                            plaintext.data() + len,
                            &len) <= 0)
        throw std::runtime_error("AES-GCM authentication failed");

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ===================== ZEROIZATION =====================

void secure_zero(std::vector<uint8_t>& buffer) {
    OPENSSL_cleanse(buffer.data(), buffer.size());
}

} // namespace uml001