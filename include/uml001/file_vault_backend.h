#pragma once

/**
 * @file file_vault_backend.h
 * @brief Rotation-capable, strong-clock-stamped IVaultBackend implementation.
 *
 * FileVaultBackend writes to a sequence of timestamped log files under
 * a base directory. Each file is named vault_<unix_ts>.log where the
 * timestamp comes from IStrongClock — ensuring tamper-evident ordering.
 *
 * Rotation archives the active file to base_dir/archive/ and opens a
 * fresh file. Read-back via read_last_line() reflects only the current
 * active file; it will NOT see lines written before the last rotation.
 *
 * For use cases that require read-back in the same session (e.g. tests
 * or single-node audit verification), use SimpleFileVaultBackend instead.
 *
 * [FIX-2] Added #include "uml001/vault.h" so IVaultBackend is visible.
 * [FIX-4] Added : public IVaultBackend inheritance so ColdVault can
 *          accept FileVaultBackend polymorphically via unique_ptr<IVaultBackend>.
 *
 * Security invariants:
 *   - All timestamps sourced from IStrongClock (never system clock directly)
 *   - fsync_on_write ensures durability against process crash mid-write
 *   - Archive directory preserves full audit history; files are never deleted
 *   - append_line() throws on any write or sync failure (fail-closed)
 */

#include "uml001/vault.h"         // [FIX-2] Provides IVaultBackend
#include "uml001/strong_clock.h"  // Provides IStrongClock

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

namespace uml001 {

// [FIX-4] Now correctly inherits IVaultBackend, enabling polymorphic use
//          inside ColdVault via std::unique_ptr<IVaultBackend>.
class FileVaultBackend : public IVaultBackend {
public:
    /**
     * @brief Construct a FileVaultBackend.
     *
     * @param base_dir       Root directory for vault files. Created if absent.
     * @param fsync_on_write If true, each append_line() call is fsynced to disk.
     *                       Set false only in controlled test environments.
     * @param strong_clock   Tamper-evident clock used to timestamp file names.
     *                       Must outlive this object.
     */
    FileVaultBackend(
        const std::filesystem::path& base_dir,
        bool fsync_on_write,
        IStrongClock& strong_clock);

    /**
     * @brief Append a line to the active vault file.
     *
     * If fsync_on_write_ is true, opens a platform file descriptor after
     * the C++ stream flush and calls fsync/_commit for durability.
     * Throws std::runtime_error on any write or sync failure (fail-closed).
     */
    void append_line(const std::string& line) override;

    /**
     * @brief Read the last non-empty line from the active vault file.
     *
     * Returns std::nullopt if the active file does not exist or is empty.
     * NOTE: Lines written before the most recent rotate() are not visible.
     */
    std::optional<std::string> read_last_line() override;

    /**
     * @brief Archive the active file and open a new timestamped file.
     *
     * The active file is moved to base_dir/archive/ before a new file
     * is opened. The archive directory is created if it does not exist.
     * Throws std::runtime_error if the active stream cannot be closed
     * or if the new file cannot be opened.
     */
    void rotate() override;

private:
    /**
     * @brief Open a new active file named vault_<strong_clock.now_unix()>.log.
     *
     * Called at construction and after each rotate(). Uses strong clock
     * time to guarantee monotonically increasing, tamper-evident filenames.
     */
    void open_new_file();

    /**
     * @brief Flush, close, and move the active file to base_dir/archive/.
     *
     * Called internally by rotate(). Does not open a replacement file.
     */
    void archive_current();

private:
    std::filesystem::path base_dir_;     // Root directory for all vault files
    std::filesystem::path active_file_;  // Path to the currently open log file

    std::ofstream stream_;               // Write stream for the active file
    bool fsync_on_write_;                // If true, fsync after every append

    IStrongClock& strong_clock_;         // Tamper-evident clock (not owned)
};

} // namespace uml001