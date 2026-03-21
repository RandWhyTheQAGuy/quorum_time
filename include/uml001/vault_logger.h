#pragma once

#include <functional>
#include <string>

namespace uml001 {

/**
 * @brief Callable type for vault audit log sinks.
 *        Receives structured (key, value) event pairs.
 */
using VaultLogSink = std::function<void(const std::string&, const std::string&)>;

/**
 * @brief Installs a global vault logger callback.
 *        Must be called once at startup before any vault_log() calls.
 *        Thread-safe after initialization.
 */
void set_vault_logger(VaultLogSink fn);

/**
 * @brief Emits a structured audit log entry to the registered sink.
 *        No-ops safely if no logger has been registered.
 * @param key    Event category, e.g. "key.rotation", "clock.sync"
 * @param value  Human-readable detail string
 */
void vault_log(const std::string& key, const std::string& value);

} // namespace uml001