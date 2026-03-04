#include "file_vault_backend.h"

#ifdef _WIN32
#include <io.h>
#define fsync _commit
#else
#include <unistd.h>
#endif

namespace uml001 {

FileVaultBackend::FileVaultBackend(
    const std::filesystem::path& base_dir,
    bool fsync_on_write,
    IStrongClock& strong_clock)
    : base_dir_(base_dir)
    , fsync_on_write_(fsync_on_write)
    , strong_clock_(strong_clock)
{
    std::filesystem::create_directories(base_dir_);
    open_new_file();
}

void FileVaultBackend::open_new_file()
{
    uint64_t ts = strong_clock_.now_unix(); // STRONG TIME

    active_file_ = base_dir_ /
        ("vault_" + std::to_string(ts) + ".log");

    stream_.open(active_file_, std::ios::app);
    if (!stream_)
        throw std::runtime_error("Failed to open vault file");
}

void FileVaultBackend::append_line(const std::string& line)
{
    stream_ << line;
    stream_.flush();

#ifndef _WIN32
    if (fsync_on_write_) {
        int fd = fileno(stream_.rdbuf()->fd());
        fsync(fd);
    }
#endif
}

std::optional<std::string> FileVaultBackend::read_last_line()
{
    if (!std::filesystem::exists(active_file_))
        return std::nullopt;

    std::ifstream in(active_file_);
    std::string line, last;
    while (std::getline(in, line))
        last = line;

    if (last.empty()) return std::nullopt;
    return last;
}

void FileVaultBackend::archive_current()
{
    stream_.close();
    auto archive_dir = base_dir_ / "archive";
    std::filesystem::create_directories(archive_dir);

    auto new_path = archive_dir / active_file_.filename();
    std::filesystem::rename(active_file_, new_path);
}

void FileVaultBackend::rotate()
{
    archive_current();
    open_new_file();
}

}