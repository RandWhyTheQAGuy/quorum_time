#pragma once
#include <cstdint>
#include <chrono>
#include <string>

namespace uml001 {

/**
 * @brief Abstract interface for trusted time sources.
 * Conforms to NIST SP 800-53 (AU-12) for authoritative time-stamping.
 */
class IStrongClock {
public:
    virtual ~IStrongClock() = default;
    
    /**
     * @brief Returns current Unix timestamp in seconds.
     */
    virtual std::uint64_t now_unix() const = 0;

    /**
     * @brief Returns the current estimated drift in microseconds.
     */
    virtual std::int64_t get_current_drift() const = 0;
};

// NOTE: IHashProvider has been moved to uml001/hash_provider.h 
// to prevent redefinition errors during compilation.

/**
 * @brief OS-backed strong clock — direct view of the system wall clock.
 */
class OsStrongClock : public IStrongClock {
public:
    std::uint64_t now_unix() const override {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()
            ).count()
        );
    }

    std::int64_t get_current_drift() const override {
        // Raw OS clock carries no drift correction.
        return 0;
    }
};

} // namespace uml001