#pragma once
#include "uml001/hash_provider.h"

namespace uml001 {

class SimpleHashProvider : public IHashProvider {
public:
    SimpleHashProvider() = default;

    // Declaration only — implementation is in the .cpp file
    std::string sha256(const std::string& data) override;
};

} // namespace uml001
