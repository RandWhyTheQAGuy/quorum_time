#pragma once

/**
 * @file simple_hash_provider.h
 * @brief Development/test hash provider implementing IHashProvider.
 *
 * NOTE: This is NOT cryptographically secure. It is only suitable for
 *       development and testing. Production should use HsmHashProvider.
 */

#include "uml001/hash_provider.h"
#include <string>

namespace uml001 {

class SimpleHashProvider : public IHashProvider {
public:
    SimpleHashProvider() = default;

    /**
     * @brief Compute a non-cryptographic hash of the input.
     *
     * This uses std::hash as a placeholder. It is NOT SHA-256.
     */
    std::string sha256(const std::string& input) override;
};

} // namespace uml001
