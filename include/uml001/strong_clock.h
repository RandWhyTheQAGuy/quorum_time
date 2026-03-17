#pragma once

#include <cstdint>

namespace uml001 {

/**
 * @brief Interface for a strong clock abstraction.
 */
class IStrongClock {
public:
    virtual ~IStrongClock() = default;

    /// Return current time as Unix seconds.
    virtual std::uint64_t now_unix() const = 0;

    /// Return current drift in seconds (can be 0 for simple clocks).
    virtual std::int64_t get_current_drift() const = 0;
};

/**
 * @brief Simple IStrongClock implementation that returns OS wall-clock time.
 *
 * Drift is always reported as 0; higher-level components (e.g. BFTQuorumTrustedClock)
 * are responsible for maintaining and applying their own drift.
 */
class OsStrongClock : public IStrongClock {
public:
    std::uint64_t now_unix() const override;
    std::int64_t get_current_drift() const override;
};

} // namespace uml001
