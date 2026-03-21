#include "uml001/simple_hash_provider.h"
#include "uml001/crypto_utils.h"

namespace uml001 {

std::string SimpleHashProvider::sha256(const std::string& data) {
    return sha256_hex(data);
}

} // namespace uml001
