#pragma once
#include "crypto_interfaces.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace uml001 {

class AESGCMProvider : public IAEADProvider {
public:
    explicit AESGCMProvider(const std::vector<uint8_t>& key)
        : key_(key) {}

    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>& nonce) override
    {
        nonce.resize(12);
        RAND_bytes(nonce.data(), 12);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data());

        int len;
        std::vector<uint8_t> ciphertext(plaintext.size());
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          plaintext.data(), plaintext.size());

        int ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
        ciphertext_len += len;

        std::vector<uint8_t> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        EVP_CIPHER_CTX_free(ctx);

        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        ciphertext.resize(ciphertext_len + 16);
        return ciphertext;
    }

    std::vector<uint8_t> decrypt(...) override {
        throw std::runtime_error("Decrypt not implemented in sample");
    }

private:
    std::vector<uint8_t> key_;
};

}