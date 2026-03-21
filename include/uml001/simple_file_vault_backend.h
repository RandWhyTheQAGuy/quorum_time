#pragma once

#include "uml001/vault.h"
#include <filesystem>
#include <optional>
#include <string>

namespace uml001 {

/**
 * @brief Lightweight single-file vault backend.
 *
 * Appends one JSON/text line per event to a single file under base_dir.
 * Intended for low-overhead deployments that do not require the full
 * FileVaultBackend rotation and fsync machinery.
 */
class SimpleFileVaultBackend : public IVaultBackend {
public:
    /**
     * @param file_path  Path to the log file (created if absent).
     *                   Accepts both std::string and std::filesystem::path
     *                   via implicit conversion.
     */
    explicit SimpleFileVaultBackend(const std::filesystem::path& file_path);

    void append_line(const std::string& line) override;
    std::optional<std::string> read_last_line() override;
    void rotate() override;

private:
    std::filesystem::path path_;
};

} // namespace uml001
