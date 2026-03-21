#include "uml001/vault_logger.h"

#include <mutex>
#include <utility>

namespace uml001 {

static VaultLogSink g_logger = nullptr;
static std::mutex g_logger_mutex;

void set_vault_logger(VaultLogSink fn) {
    std::lock_guard<std::mutex> lock(g_logger_mutex);
    g_logger = std::move(fn);
}

void vault_log(const std::string& key, const std::string& value) {
    VaultLogSink fn_copy;
    {
        std::lock_guard<std::mutex> lock(g_logger_mutex);
        fn_copy = g_logger;
    }

    if (!fn_copy) {
        return;  // <-- prevents segfault
    }

    fn_copy(key, value);
}

} // namespace uml001
