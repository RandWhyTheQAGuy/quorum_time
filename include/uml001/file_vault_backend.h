#pragma once

/**
 * @file file_vault_backend.h
 * @brief Rotation-capable, strong-clock-stamped IVaultBackend implementation.
 *
 * FileVaultBackend writes to a sequence of timestamped log files under
 * a base directory. Each file is named vault_<unix_ts>.log where the
 * timestamp comes from IStrongClock — ensuring tamper-evident ordering.
 */

#include "uml001/vault.h"         
#include "uml001/strong_clock.h"  

#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

namespace uml001 {

/**
 * @brief Implementation of IVaultBackend supporting file rotation.
 * * NOTE: Ensure that IVaultBackend in vault.h defines these methods 
 * as 'virtual' or the compiler will throw an 'only virtual member 
 * functions can be marked override' error.
 */
class FileVaultBackend : public IVaultBackend {
public:
    /**
     * @brief Construct a FileVaultBackend.
     *
     * @param base_dir       Root directory for vault files. Created if absent.
     * @param fsync_on_write If true, each append_line() call is fsynced to disk.
     * @param strong_clock   Tamper-evident clock used to timestamp file names.
     */
    FileVaultBackend(
        const std::filesystem::path& base_dir,
        bool fsync_on_write,
        IStrongClock& strong_clock);

    // Virtual destructor is essential for polymorphic cleanup via unique_ptr
    virtual ~FileVaultBackend() override = default;

    /**
     * @brief Append a line to the active vault file.
     * Implements IVaultBackend::append_line.
     */
    void append_line(const std::string& line) override;

    /**
     * @brief Read the last non-empty line from the active vault file.
     * Implements IVaultBackend::read_last_line.
     */
    std::optional<std::string> read_last_line() override;

    /**
     * @brief Archive the active file and open a new timestamped file.
     * Implements IVaultBackend::rotate.
     */
    void rotate() override;

private:
    /**
     * @brief Open a new active file named vault_<strong_clock.now_unix()>.log.
     */
    void open_new_file();

    /**
     * @brief Flush, close, and move the active file to base_dir/archive/.
     */
    void archive_current();

private:
    std::filesystem::path base_dir_;     
    std::filesystem::path active_file_;  

    std::ofstream stream_;               
    bool fsync_on_write_;                

    IStrongClock& strong_clock_;         // Reference to the injected clock
};

} // namespace uml001