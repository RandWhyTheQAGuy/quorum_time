#include "vault.h"
#include <sstream>

namespace uml001 {

ColdVault::ColdVault(Config config,
                     std::unique_ptr<IVaultBackend> backend,
                     IStrongClock& strong_clock,
                     IHashProvider& hash_provider)
    : config_(std::move(config))
    , backend_(std::move(backend))
    , strong_clock_(strong_clock)
    , hash_provider_(hash_provider)
{
    std::filesystem::create_directories(config_.base_directory);
    current_file_start_time_ = strong_clock_.now_unix();

    auto last_line = backend_->read_last_line();
    if (last_line) {
        auto pos = last_line->find("hash=");
        if (pos != std::string::npos)
            last_hash_ = last_line->substr(pos + 5);
    }
}

void ColdVault::log_sync_event(uint64_t agreed_time,
                               int64_t drift_step,
                               int64_t total_drift)
{
    std::lock_guard<std::mutex> lock(mutex_);

    maybe_rotate();

    std::string entry = build_log_entry(agreed_time,
                                        drift_step,
                                        total_drift);

    backend_->append_line(entry);
    current_file_size_ += entry.size();
}

std::string ColdVault::build_log_entry(uint64_t agreed_time,
                                       int64_t drift_step,
                                       int64_t total_drift)
{
    uint64_t timestamp = strong_clock_.now_unix(); // STRONG TIME

    std::ostringstream oss;
    oss << "ts=" << timestamp
        << " agreed=" << agreed_time
        << " drift_step=" << drift_step
        << " total_drift=" << total_drift
        << " prev_hash=" << last_hash_;

    std::string content = oss.str();
    std::string hash = hash_provider_.sha256(content);

    last_hash_ = hash;

    return content + " hash=" + hash + "\n";
}

void ColdVault::maybe_rotate()
{
    uint64_t now = strong_clock_.now_unix(); // STRONG TIME

    if (current_file_size_ >= config_.max_file_size_bytes ||
        (now - current_file_start_time_) >= config_.max_file_age_seconds)
    {
        backend_->rotate();
        current_file_start_time_ = now;
        current_file_size_ = 0;
        last_hash_ = "ROTATE_BOUNDARY";
    }
}

std::optional<int64_t> ColdVault::load_last_drift()
{
    auto last_line = backend_->read_last_line();
    if (!last_line) return std::nullopt;

    auto pos = last_line->find("total_drift=");
    if (pos == std::string::npos) return std::nullopt;

    return std::stoll(last_line->substr(pos + 12));
}

}