#pragma once
#include <cstdint>

namespace uml001 {

class ClockGovernor {
public:
    explicit ClockGovernor(uint32_t required_observations)
        : required_(required_observations) {}

    bool update_and_check(uint32_t obs_count) {
        if (obs_count >= required_) return true;
        return false;
    }

private:
    uint32_t required_;
};

} // namespace uml001
