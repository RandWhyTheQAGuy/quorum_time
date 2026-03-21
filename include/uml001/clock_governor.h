#pragma once

#include <cstdint>
#include <mutex>
#include <atomic>

namespace uml001 {

/**
 * @brief Manages the "Cold Start" safety protocol.
 * * The Governor prevents the system from reporting its time as "Trusted" 
 * until a minimum number of successful quorum observations have been 
 * witnessed since process start.
 */
class ClockGovernor {
public:
    /**
     * @param quorum_threshold The number of agreeing authorities required 
     * to exit Cold Start.
     */
    explicit ClockGovernor(uint32_t quorum_threshold)
        : threshold_(quorum_threshold), current_count_(0), operational_(false) {}

    /**
     * @brief Updates the governor with the count of valid observations from a sync round.
     * @return true if the system has reached or already passed the quorum threshold.
     */
    bool update_and_check(size_t valid_observations) {
        std::lock_guard<std::mutex> lock(mtx_);
        
        // Update the current count (in a real system, this might track unique IDs)
        current_count_ = static_cast<uint32_t>(valid_observations);

        if (current_count_ >= threshold_) {
            operational_ = true;
        }
        return operational_;
    }

    /**
     * @brief Returns the status of the clock bootstrapping.
     */
    bool is_operational() const {
        return operational_.load();
    }

    /**
     * @brief Returns the threshold required for bootstrapping.
     */
    uint32_t threshold() const {
        return threshold_;
    }

    /**
     * @brief Returns the last recorded observation count.
     */
    uint32_t current_count() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return current_count_;
    }

private:
    const uint32_t     threshold_;
    uint32_t           current_count_;
    std::atomic<bool>  operational_;
    mutable std::mutex mtx_;
};

} // namespace uml001