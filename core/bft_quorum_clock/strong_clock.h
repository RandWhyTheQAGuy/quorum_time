#pragma once
#include <cstdint>

namespace uml001 {

/**
 * IStrongClock
 *
 * All security-sensitive time must come from this interface.
 * Only BFTQuorumTrustedClock may access OS clock.
 */
class IStrongClock {
public:
    virtual ~IStrongClock() = default;
    virtual uint64_t now_unix() const = 0;
};

}