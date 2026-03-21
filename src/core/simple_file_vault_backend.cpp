#include "uml001/simple_file_vault_backend.h"

#include <fstream>
#include <stdexcept>
#include <filesystem>

namespace uml001 {

SimpleFileVaultBackend::SimpleFileVaultBackend(const std::filesystem::path& input_path)
{
    // 🔥 FIX: Treat input as directory if it doesn't look like a file
    if (input_path.has_extension()) {
        // Explicit file path
        path_ = input_path;
        std::filesystem::create_directories(path_.parent_path());
    } else {
        // Directory path (this is what tests use)
        std::filesystem::create_directories(input_path);
        path_ = input_path / "vault.log";
    }

    // 🔥 Ensure file exists
    std::ofstream out(path_, std::ios::app);
    if (!out.is_open()) {
        throw std::runtime_error(
            "SimpleFileVaultBackend: Initial file creation/access failed: " + path_.string()
        );
    }
}

void SimpleFileVaultBackend::append_line(const std::string& line)
{
    std::ofstream out(path_, std::ios::app | std::ios::binary);
    if (!out.is_open()) {
        throw std::runtime_error("SimpleFileVaultBackend: Failed to open file for append");
    }

    out << line << "\n";

    if (!out.good()) {
        throw std::runtime_error("SimpleFileVaultBackend: Write failed");
    }
}

std::optional<std::string> SimpleFileVaultBackend::read_last_line()
{
    if (!std::filesystem::exists(path_)) {
        return std::nullopt;
    }

    std::ifstream in(path_, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return std::nullopt;
    }

    std::string line;
    std::string last;

    while (std::getline(in, line)) {
        if (!line.empty()) {
            last = line;
        }
    }

    if (last.empty()) return std::nullopt;
    return last;
}

void SimpleFileVaultBackend::rotate()
{
    // No-op for simple backend
}

} // namespace uml001