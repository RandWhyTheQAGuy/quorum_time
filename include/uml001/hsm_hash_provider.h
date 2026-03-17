#pragma once
#include "uml001/hash_provider.h"

namespace uml001 {

class HSMHashProvider : public IHashProvider {
public:
    HSMHashProvider(/* PKCS#11 session handle */) {}

    std::string sha256(const std::string& data) override {
        // In production:
        // - C_DigestInit
        // - C_DigestUpdate
        // - C_DigestFinal
        // Returns hex string
        return "HSM_SHA256_PLACEHOLDER";
    }
};

} // namespace uml001
