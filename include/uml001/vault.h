#pragma once

#include "uml001/strong_clock.h"
#include "uml001/hash_provider.h"
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace uml001 {

/**
 * @brief Interface for vault storage backends.
 */
class IVaultBackend {
public:
    virtual ~IVaultBackend() = default;
    virtual void append_line(const std::string& line) = 0;
    virtual std::optional<std::string> read_last_line() = 0;
    virtual void rotate() = 0;
};

/**
 * @brief ColdVault maintains a tamper-evident audit log for drift and key rotations.
 */
class ColdVault {
public:
    // --- Config struct ---
    struct Config {
        std::filesystem::path base_directory;
        uint64_t max_file_size_bytes  = 10 * 1024 * 1024;
        uint64_t max_file_age_seconds = 86400;
    };

    // Correctly qualified getter
    const ColdVault::Config& config() const { return cfg_; }

    // Constructor now accepts shared_ptr for Pybind11 compatibility
    ColdVault(const Config& cfg, 
              std::shared_ptr<IVaultBackend> backend, 
              IStrongClock& clock, 
              IHashProvider& hasher);

    // Drift persistence
    void save_last_drift(std::int64_t drift);
    std::optional<std::int64_t> load_last_drift();

    // Authority sequences
    void save_authority_sequences(const std::unordered_map<std::string, std::uint64_t>& seqs);
    std::unordered_map<std::string, std::uint64_t> load_authority_sequences();

    // Logging
    void log_sync_event(std::uint64_t agreed_time, std::int64_t drift_step, std::int64_t total_drift);
    void log_security_event(const std::string& event_type, const std::string& details);
    void log_key_rotation_event(uint64_t key_version, uint64_t unix_time);

private:
    void ensure_directories();
    void maybe_rotate();

    ColdVault::Config               cfg_;       // Qualified type
    std::shared_ptr<IVaultBackend>  backend_;   // Matches constructor
    IStrongClock&                   clock_;
    IHashProvider&                  hash_;

    std::mutex                      mutex_;
    std::filesystem::path           drift_file_;
    std::filesystem::path           seq_file_;
    std::string                     last_hash_;
    uint64_t                        current_file_start_time_ = 0;
    uint64_t                        current_file_size_       = 0;
};

} // namespace uml001