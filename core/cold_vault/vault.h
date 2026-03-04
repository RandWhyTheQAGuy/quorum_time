#pragma once

#include <string>
#include <mutex>
#include <optional>
#include <memory>
#include <filesystem>

#include "strong_clock.h"
#include "crypto_interfaces.h"

namespace uml001 {

class IVaultBackend {
public:
    virtual ~IVaultBackend() = default;
    virtual void append_line(const std::string& line) = 0;
    virtual std::optional<std::string> read_last_line() = 0;
    virtual void rotate() = 0;
};

class ColdVault {
public:
    struct Config {
        std::filesystem::path base_directory;
        size_t max_file_size_bytes = 10 * 1024 * 1024;
        uint64_t max_file_age_seconds = 86400;
        bool fsync_on_write = true;
    };

    ColdVault(Config config,
              std::unique_ptr<IVaultBackend> backend,
              IStrongClock& strong_clock,
              IHashProvider& hash_provider);

    void log_sync_event(uint64_t agreed_time,
                        int64_t drift_step,
                        int64_t total_drift);

    std::optional<int64_t> load_last_drift();

private:
    std::string build_log_entry(uint64_t agreed_time,
                                int64_t drift_step,
                                int64_t total_drift);

    void maybe_rotate();

    Config config_;
    std::unique_ptr<IVaultBackend> backend_;
    IStrongClock& strong_clock_;
    IHashProvider& hash_provider_;

    std::mutex mutex_;
    std::string last_hash_ = "GENESIS";
    uint64_t current_file_start_time_;
    size_t current_file_size_ = 0;
};

}