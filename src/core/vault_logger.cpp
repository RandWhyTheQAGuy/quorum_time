#include "uml001/vault_logger.h"
#include <mutex>        // ← REQUIRED
#include <utility>      // for std::move

namespace uml001 {

// Global logger callback (protected by mutex)
static VaultLogSink g_logger = nullptr;
static std::mutex g_logger_mutex;

/**
 * Install a global vault logger callback.
 */
void set_vault_logger(VaultLogSink fn) {
    std::lock_guard<std::mutex> lock(g_logger_mutex);
    g_logger = std::move(fn);
}

/**
 * Emit a vault log event through the installed callback.
 */
void vault_log(const std::string& key,
               const std::string& value)
{
    VaultLogSink fn_copy;

    {
        std::lock_guard<std::mutex> lock(g_logger_mutex);
        fn_copy = g_logger;  // copy under lock
    }

    if (fn_copy) {
        fn_copy(key, value); // invoke outside lock
    }
}

} // namespace uml001
