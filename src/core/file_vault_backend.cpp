#include "uml001/file_vault_backend.h"

#include <stdexcept>
#include <fstream>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
    // On Windows, _commit is the equivalent of fsync
    #define fsync _commit
    #define open_fd  _open
    #define close_fd _close
#else
    #include <unistd.h>
    #include <fcntl.h>
    #define open_fd  ::open
    #define close_fd ::close
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
    const uint64_t ts = strong_clock_.now_unix(); // STRONG TIME

    active_file_ = base_dir_ /
        ("vault_" + std::to_string(ts) + ".log");

    // Append in binary mode for consistent behavior across platforms
    stream_.open(active_file_, std::ios::app | std::ios::binary);
    if (!stream_) {
        throw std::runtime_error(
            "Failed to open vault file: " + active_file_.string());
    }
}

void FileVaultBackend::append_line(const std::string& line)
{
    if (!stream_) {
        throw std::runtime_error("append_line called on closed vault stream");
    }

    stream_ << line;
    stream_.flush();

    if (!stream_) {
        throw std::runtime_error("Failed to write to vault file: " +
                                 active_file_.string());
    }

    if (fsync_on_write_) {
        // We ensure durability by:
        // 1. Flushing the C++ stream (done above)
        // 2. Opening a platform fd on the same file path
        // 3. Calling fsync/_commit on that fd
        // 4. Closing the fd
        //
        // This is portable and does not rely on non-standard filebuf::fd().
#ifdef _WIN32
        int fd = open_fd(
            active_file_.string().c_str(),
            _O_WRONLY | _O_APPEND | _O_BINARY,
            _S_IREAD | _S_IWRITE
        );
#else
        int fd = open_fd(
            active_file_.c_str(),
            O_WRONLY | O_APPEND
        );
#endif
        if (fd < 0) {
            throw std::runtime_error(
                "Failed to open file descriptor for fsync: " +
                active_file_.string());
        }

        if (fsync(fd) != 0) {
            close_fd(fd);
            throw std::runtime_error(
                "fsync failed for vault file: " + active_file_.string());
        }

        close_fd(fd);
    }
}

std::optional<std::string> FileVaultBackend::read_last_line()
{
    if (!std::filesystem::exists(active_file_)) {
        return std::nullopt;
    }

    std::ifstream in(active_file_, std::ios::in | std::ios::binary);
    if (!in) {
        return std::nullopt;
    }

    std::string line;
    std::string last;

    while (std::getline(in, line)) {
        last = line;
    }

    if (last.empty()) {
        return std::nullopt;
    }
    return last;
}

void FileVaultBackend::archive_current()
{
    if (stream_.is_open()) {
        stream_.flush();
        stream_.close();
    }

    const auto archive_dir = base_dir_ / "archive";
    std::filesystem::create_directories(archive_dir);

    const auto new_path = archive_dir / active_file_.filename();
    std::filesystem::rename(active_file_, new_path);
}

void FileVaultBackend::rotate()
{
    archive_current();
    open_new_file();
}

} // namespace uml001
