#pragma once

/**
 * @file simple_file_vault_backend.h
 * @brief Minimal IVaultBackend implementation that appends to a single file.
 *
 * This backend:
 *   - Appends each log line to audit.log in the given directory
 *   - Can read the last non-empty line via read_last_line()
 *   - Can read all non-empty lines via read_all() — required for test
 *     assertions that scan the full audit history
 *   - Supports a trivial "rotate" by truncating the file
 *
 * Security invariants:
 *   - All writes are append-only; truncation only occurs on explicit rotate()
 *   - read_all() scans the full file on each call — no caching — so callers
 *     always see the authoritative on-disk state
 *   - No timestamps are injected by this backend; timestamping is the
 *     responsibility of ColdVault and its callers
 *
 * This is the correct backend for:
 *   - Single-node production deployments requiring same-session read-back
 *   - All test scenarios that inspect vault audit contents
 *
 * For rotation-capable, strong-clock-stamped deployments use FileVaultBackend.
 *
 * [FIX-12] Added read_all() declaration and #include <vector>.
 *           Required by test assertions of the form:
 *             any("sync.committed" in line for line in backend.read_all())
 *           The .cpp implementation scans audit.log on every call with
 *           no caching so callers always see the authoritative on-disk state.
 */

#include "uml001/vault.h"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>      // [FIX-12] Required for read_all() return type

namespace uml001 {

class SimpleFileVaultBackend : public IVaultBackend {
public:
    /**
     * @brief Construct a SimpleFileVaultBackend.
     *
     * @param dir  Directory in which audit.log will be created.
     *             The directory is created if it does not exist.
     */
    explicit SimpleFileVaultBackend(const std::filesystem::path& dir);

    /**
     * @brief Append a line to audit.log.
     *
     * A newline is appended automatically. Throws std::runtime_error
     * if the file cannot be opened or written (fail-closed).
     */
    void append_line(const std::string& line) override;

    /**
     * @brief Read the last non-empty line from audit.log.
     *
     * Returns std::nullopt if the file does not exist or contains no
     * non-empty lines. Scans the full file on each call.
     */
    std::optional<std::string> read_last_line() override;

    /**
     * @brief Read all non-empty lines from audit.log.
     *
     * Returns an empty vector if the file does not exist or is empty.
     * Scans the full file on each call — always reflects on-disk state.
     * No caching is performed.
     *
     * [FIX-12] Added to support test assertions that scan the full
     * audit history, e.g.:
     *   any("sync.committed" in line for line in backend.read_all())
     */
    std::vector<std::string> read_all();

    /**
     * @brief Truncate audit.log (trivial rotation).
     *
     * All existing content is discarded. A new empty file is created.
     * Use only in controlled test environments or when archival is not
     * required. For archival-safe rotation use FileVaultBackend.
     */
    void rotate() override;

private:
    std::filesystem::path path_;  // Full path to audit.log
};

} // namespace uml001