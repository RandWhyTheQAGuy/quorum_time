#pragma once

#include <cstdint>

/**
 * SharedClockState
 *
 * Redis-published consensus time state.
 * Versioned and cryptographically bound to key version.
 */

struct SharedClockState {
    uint64_t agreed_time;
    int64_t  applied_drift;
    uint64_t last_updated_unix;
    uint64_t key_version;
};