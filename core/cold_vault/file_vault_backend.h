#pragma once

#include "vault.h"
#include "strong_clock.h"
#include <fstream>

namespace uml001 {

class FileVaultBackend : public IVaultBackend {
public:
    FileVaultBackend(const std::filesystem::path& base_dir,
                     bool fsync_on_write,
                     IStrongClock& strong_clock);

    void append_line(const std::string& line) override;
    std::optional<std::string> read_last_line() override;
    void rotate() override;

private:
    void open_new_file();
    void archive_current();

    std::filesystem::path base_dir_;
    std::filesystem::path active_file_;
    std::ofstream stream_;
    bool fsync_on_write_;
    IStrongClock& strong_clock_;
};

}