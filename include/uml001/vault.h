#pragma once

/**
 * @file vault.h
 * @brief ColdVault: append-only, tamper-evident audit log + drift/sequence persistence.
 *
 * The vault is intentionally simple:
 *   - append_line() is provided by IVaultBackend
 *   - ColdVault adds structured audit helpers on top
 *   - No virtual methods for Python override (Python wraps, not subclasses)
 *
 * Audit log entry formats are schematised in bft_quorum_clock_schema.h.
 * All parameter names on log_*() methods must match the corresponding
 * schema field names exactly to ensure the schema remains the authoritative
 * contract for the wire format.
 *
 * [FIX-19] log_sync_event parameter names corrected to match
 *           BFT_VAULT_SYNC_LOG_SCHEMA field names:
 *             applied_drift -> drift_step
 *             local_drift   -> current_drift
 *           The previous names were inconsistent with the published schema,
 *           meaning the schema documented a format the implementation never
 *           produced under those names. All call sites must be updated.
 */

#include <string>
#include <optional>
#include <memory>
#include <unordered_map>
#include <filesystem>
#include <mutex>

#include "uml001/strong_clock.h"
#include "uml001/hash_provider.h"

namespace uml001 {

// ============================================================
// Backend Interface
// ============================================================

class IVaultBackend {
public:
    virtual ~IVaultBackend() = default;

    /**
     * @brief Append a line to the vault's active storage.
     * Implementations must be fail-closed: throw on any write failure.
     */
    virtual void append_line(const std::string& line) = 0;

    /**
     * @brief Read the last non-empty line from active storage.
     * Returns std::nullopt if storage is absent or empty.
     */
    virtual std::optional<std::string> read_last_line() = 0;

    /**
     * @brief Rotate the active storage (archive or truncate).
     */
    virtual void rotate() = 0;
};

// ============================================================
// ColdVault
// ============================================================

class ColdVault {
public:
    struct Config {
        std::filesystem::path base_directory;
        uint64_t max_file_size_bytes  = 10 * 1024 * 1024; // 10 MiB
        uint64_t max_file_age_seconds = 86400;             // 24 hours
        bool     fsync_on_write       = true;
    };

    ColdVault(const Config&                  cfg,
              std::unique_ptr<IVaultBackend> backend,
              IStrongClock&                  clock,
              IHashProvider&                 hash);

    ~ColdVault() = default;

    // --------------------------------------------------------
    // Audit Logging
    //
    // All log_*() methods produce structured, hash-chained entries
    // in the vault's audit log. Entries are schematised in
    // bft_quorum_clock_schema.h and must not be reordered or renamed
    // without updating the corresponding schema.
    // --------------------------------------------------------

    /**
     * @brief Append a structured security event entry.
     *
     * Produces a BFT_VAULT_SECURITY_SCHEMA-compliant entry.
     * key must follow the "bft.<subsystem>.<event>" pattern.
     * detail must not contain HMAC key material or secrets.
     */
    void log_security_event(const std::string& key,
                            const std::string& detail);

    /**
     * @brief Append a BFT sync commit entry.
     *
     * Produces a BFT_VAULT_SYNC_LOG_SCHEMA-compliant entry.
     *
     * @param agreed_time   BFT-agreed unix timestamp committed this round.
     * @param drift_step    Drift correction applied this round (signed, seconds).
     *                      Maps to schema field "drift_step".
     * @param current_drift Cumulative drift after this round (signed, seconds).
     *                      Maps to schema field "current_drift".
     *
     * [FIX-19] Parameters renamed from (agreed_time, applied_drift, local_drift)
     *           to (agreed_time, drift_step, current_drift) to match
     *           BFT_VAULT_SYNC_LOG_SCHEMA field names exactly.
     */
    void log_sync_event(uint64_t agreed_time,
                        int64_t  drift_step,
                        int64_t  current_drift);

    /**
     * @brief Append a key rotation event entry.
     *
     * @param new_version  New key version number.
     * @param unix_time    Unix timestamp of the rotation event.
     */
    void log_key_rotation_event(uint64_t new_version,
                                uint64_t unix_time);

    // --------------------------------------------------------
    // Drift Persistence (cold-start recovery)
    // --------------------------------------------------------

    /**
     * @brief Load the last persisted drift value.
     * Returns std::nullopt on a fresh vault with no prior state.
     */
    std::optional<int64_t> load_last_drift();

    /**
     * @brief Persist the current drift value for cold-start recovery.
     */
    void save_last_drift(int64_t drift);

    // --------------------------------------------------------
    // Sequence Persistence (replay-attack prevention)
    // --------------------------------------------------------

    /**
     * @brief Load persisted per-authority sequence numbers.
     * Returns an empty map on a fresh vault with no prior state.
     */
    std::unordered_map<std::string, uint64_t>
    load_authority_sequences();

    /**
     * @brief Persist per-authority sequence numbers.
     */
    void save_authority_sequences(
        const std::unordered_map<std::string, uint64_t>& seqs);

private:
    // Config + dependencies (set at construction, never mutated)
    Config                         cfg_;
    std::unique_ptr<IVaultBackend> backend_;
    IStrongClock&                  clock_;
    IHashProvider&                 hash_;

    // Rotation state
    uint64_t    current_file_start_time_ = 0;
    uint64_t    current_file_size_       = 0;
    std::string last_hash_               = "GENESIS";

    // Persistence file paths (derived from cfg_.base_directory)
    std::filesystem::path drift_file_;
    std::filesystem::path seq_file_;

    // Thread safety — all public methods acquire this lock
    std::mutex mutex_;

    // Internal helpers
    void ensure_directories();
    void maybe_rotate();
};

} // namespace uml001