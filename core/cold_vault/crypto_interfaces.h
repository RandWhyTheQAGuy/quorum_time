#pragma once
#include <string>
#include <vector>

namespace uml001 {

class IHashProvider {
public:
    virtual ~IHashProvider() = default;
    virtual std::string sha256(const std::string& data) = 0;
};

class ISignProvider {
public:
    virtual ~ISignProvider() = default;
    virtual std::vector<uint8_t> sign(const std::vector<uint8_t>& data) = 0;
    virtual bool verify(const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& sig) = 0;
};

class IAEADProvider {
public:
    virtual ~IAEADProvider() = default;

    virtual std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>& out_nonce) = 0;

    virtual std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& nonce) = 0;
};

}