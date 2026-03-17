#include "uml001/simple_hash_provider.h"

#include <functional>
#include <sstream>
#include <iomanip>

namespace uml001 {

std::string SimpleHashProvider::sha256(const std::string& input) {
    // WARNING: This is NOT cryptographically secure.
    // It is only a placeholder for development/testing.
    std::hash<std::string> h;
    auto v = h(input);

    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << v;
    return oss.str();
}

} // namespace uml001
