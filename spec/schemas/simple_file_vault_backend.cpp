#include "uml001/simple_file_vault_backend.h"

#include <filesystem>
#include <fstream>

namespace uml001 {

SimpleFileVaultBackend::SimpleFileVaultBackend(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    path_ = dir / "audit.log";
}

void SimpleFileVaultBackend::append_line(const std::string& line) {
    std::ofstream out(path_, std::ios::app);
    out << line;
}

std::optional<std::string> SimpleFileVaultBackend::read_last_line() {
    std::ifstream in(path_);
    if (!in) return std::nullopt;

    std::string line, last;
    while (std::getline(in, line)) {
        if (!line.empty()) last = line;
    }
    if (last.empty()) return std::nullopt;
    return last;
}

void SimpleFileVaultBackend::rotate() {
    std::ofstream out(path_, std::ios::trunc);
}

} // namespace uml001
