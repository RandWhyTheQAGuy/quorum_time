#include "uml001/vault.h"
#include <fstream>
#include <sstream>

namespace uml001 {

// ============================================================
// Constructor
// ============================================================

ColdVault::ColdVault(const Config& cfg,
                     std::unique_ptr<IVaultBackend> backend,
                     IStrongClock& clock,
                     IHashProvider& hash)
    : cfg_(cfg)
    , backend_(std::move(backend))
    , clock_(clock)
    , hash_(hash)
{
    ensure_directories();

    drift_file_ = cfg_.base_directory / "drift.state";
    seq_file_   = cfg_.base_directory / "authority_sequences.state";

    current_file_start_time_ = clock_.now_unix();

    auto last_line = backend_->read_last_line();
    if (last_line) {
        auto pos = last_line->find("hash=");
        if (pos != std::string::npos)
            last_hash_ = last_line->substr(pos + 5);
    }
}

// ============================================================
// Directory setup
// ============================================================

void ColdVault::ensure_directories()
{
    std::filesystem::create_directories(cfg_.base_directory);
}

// ============================================================
// Audit Logging
// ============================================================

void ColdVault::log_security_event(const std::string& key,
                                   const std::string& detail)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = clock_.now_unix();

    std::ostringstream oss;
    oss << "ts=" << ts
        << " type=security"
        << " key=" << key
        << " detail=" << detail
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash    = hash_.sha256(content);

    last_hash_ = hash;

    backend_->append_line(content + " hash=" + hash + "\n");
    current_file_size_ += content.size() + hash.size() + 7;
}

void ColdVault::log_sync_event(uint64_t agreed_time,
                               int64_t drift_step,
                               int64_t total_drift)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    uint64_t ts = clock_.now_unix();

    std::ostringstream oss;
    oss << "ts=" << ts
        << " type=sync"
        << " agreed=" << agreed_time
        << " drift_step=" << drift_step
        << " total_drift=" << total_drift
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash    = hash_.sha256(content);

    last_hash_ = hash;

    backend_->append_line(content + " hash=" + hash + "\n");
    current_file_size_ += content.size() + hash.size() + 7;
}

void ColdVault::log_key_rotation_event(uint64_t new_version,
                                       uint64_t unix_time)
{
    std::lock_guard<std::mutex> lock(mutex_);
    maybe_rotate();

    std::ostringstream oss;
    oss << "ts=" << unix_time
        << " type=key_rotation"
        << " version=" << new_version
        << " prev_hash=" << last_hash_;

    const std::string content = oss.str();
    const std::string hash    = hash_.sha256(content);

    last_hash_ = hash;

    backend_->append_line(content + " hash=" + hash + "\n");
    current_file_size_ += content.size() + hash.size() + 7;
}

// ============================================================
// Rotation
// ============================================================

void ColdVault::maybe_rotate()
{
    uint64_t now = clock_.now_unix();

    if (current_file_size_ >= cfg_.max_file_size_bytes ||
        (now - current_file_start_time_) >= cfg_.max_file_age_seconds)
    {
        backend_->rotate();
        current_file_start_time_ = now;
        current_file_size_ = 0;
        last_hash_ = "ROTATE_BOUNDARY";
    }
}

// ============================================================
// Drift Persistence
// ============================================================

std::optional<int64_t> ColdVault::load_last_drift()
{
    std::ifstream in(drift_file_);
    if (!in) return std::nullopt;

    int64_t v = 0;
    in >> v;
    if (in.fail()) return std::nullopt;
    return v;
}

void ColdVault::save_last_drift(int64_t drift)
{
    std::ofstream out(drift_file_, std::ios::trunc);
    out << drift;
}

// ============================================================
// Authority Sequence Persistence
// ============================================================

std::unordered_map<std::string, uint64_t>
ColdVault::load_authority_sequences()
{
    std::unordered_map<std::string, uint64_t> out;

    std::ifstream in(seq_file_);
    if (!in) return out;

    std::string line;
    while (std::getline(in, line)) {
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        uint64_t val    = std::stoull(line.substr(pos + 1));
        out[key] = val;
    }

    return out;
}

void ColdVault::save_authority_sequences(
    const std::unordered_map<std::string, uint64_t>& seqs)
{
    std::ofstream out(seq_file_, std::ios::trunc);
    for (const auto& kv : seqs) {
        out << kv.first << "=" << kv.second << "\n";
    }
}

} // namespace uml001
