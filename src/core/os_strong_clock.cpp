#include "uml001/strong_clock.h"

#include <chrono>

namespace uml001 {

std::uint64_t OsStrongClock::now_unix() const {
    using namespace std::chrono;
    return duration_cast<seconds>(
        system_clock::now().time_since_epoch()
    ).count();
}

std::int64_t OsStrongClock::get_current_drift() const {
    return 0;
}

} // namespace uml001
