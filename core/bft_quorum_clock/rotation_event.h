#pragma once

#include <cstdint>

/**
 * KeyRotationEvent
 *
 * Persisted in ColdVault for audit trail.
 */

struct KeyRotationEvent {
    uint64_t key_version;
    uint64_t rotation_time_unix;
};