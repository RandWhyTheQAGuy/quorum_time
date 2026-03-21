#pragma once
/**
 * @file hardened_clock.h
 * @brief Logic for Quorum-First Initialization and state transitions.
 */

#include <string>
#include <atomic>
#include <cstdint>

namespace uml001 {

/**
 * @enum TrustLevel
 * @brief Defines the operational readiness of the Aegis Clock.
 */
enum class TrustLevel {
    COLD_BOOT,      ///< No data yet; clock is strictly local and untrusted.
    WARMING,        ///< Receiving data but below BFT quorum (N < 3F+1).
    STABLE_QUORUM,  ///< Full BFT consensus reached; safe for production use.
    DEGRADED        ///< Previously stable, but quorum has been lost.
};

class ClockGovernor {
public:
    explicit ClockGovernor(uint32_t min_quorum) : min_quorum_(min_quorum) {}

    /**
     * @brief Updates state based on observation count and returns true if trusted.
     */
    bool update_and_check(size_t observation_count) {
        if (observation_count >= min_quorum_) {
            state_ = TrustLevel::STABLE_QUORUM;
            return true;
        }
        
        if (state_ == TrustLevel::STABLE_QUORUM && observation_count < min_quorum_) {
            state_ = TrustLevel::DEGRADED;
        } else if (observation_count > 0 && state_ == TrustLevel::COLD_BOOT) {
            state_ = TrustLevel::WARMING;
        }
        return (state_ == TrustLevel::STABLE_QUORUM);
    }

    TrustLevel get_state() const { return state_; }
    uint32_t get_min_quorum() const { return min_quorum_; }

private:
    TrustLevel state_ = TrustLevel::COLD_BOOT;
    uint32_t min_quorum_;
};

} // namespace uml001