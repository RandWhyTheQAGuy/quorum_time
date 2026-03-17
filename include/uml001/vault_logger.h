#pragma once

/**
 * @file vault_logger.h
 * @brief Global vault logging hook for routing audit events.
 *
 * This module provides:
 *   - set_vault_logger(): install a global callback
 *   - vault_log(): emit an event through the callback
 *
 * Python bindings and main_ntp.cpp both rely on this.
 */

#include <functional>
#include <string>

namespace uml001 {

/**
 * @brief Function signature for vault log sinks.
 *
 * key    = event name (e.g., "clock.sync")
 * value  = event detail (e.g., "promoted BFT time")
 */
using VaultLogSink = std::function<void(const std::string& key,
                                        const std::string& value)>;

/**
 * @brief Install a global vault logger callback.
 *
 * Thread-safe. Replaces any previously installed logger.
 */
void set_vault_logger(VaultLogSink fn);

/**
 * @brief Emit a vault log event through the installed callback.
 *
 * If no logger is installed, this is a no-op.
 * Thread-safe.
 */
void vault_log(const std::string& key,
               const std::string& value);

} // namespace uml001
