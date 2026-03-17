#pragma once

/**
 * @file hash_provider.h
 * @brief Abstract interface for SHA-256 hashing used by ColdVault and BFT clock.
 *
 * Implementations:
 *   - SimpleHashProvider (software fallback)
 *   - HsmHashProvider (hardware-backed)
 */

#include <string>

namespace uml001 {

class IHashProvider {
public:
    virtual ~IHashProvider() = default;

    /**
     * @brief Compute SHA-256 hash of the input and return lowercase hex.
     */
    virtual std::string sha256(const std::string& input) = 0;
};

} // namespace uml001
