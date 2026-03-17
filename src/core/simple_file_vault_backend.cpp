// src/core/simple_file_vault_backend.cpp
//
// Implementation of SimpleFileVaultBackend — minimal append-only
// IVaultBackend backed by a single file (audit.log).
//
// Security invariants maintained here:
//   - All writes are append-only; the file is never truncated except
//     on an explicit rotate() call
//   - read_all() and read_last_line() scan the full file on every call —
//     no caching — so callers always see the authoritative on-disk state
//   - append_line() throws std::runtime_error on any write failure
//     (fail-closed: no silent data loss)
//   - rotate() truncates by replacing the file with an empty one;
//     no archival is performed — use FileVaultBackend if archival is needed
//   - No timestamps are injected by this backend; timestamping is the
//     responsibility of ColdVault and its callers

#include "uml001/simple_file_vault_backend.h"

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>

namespace uml001 {

// ============================================================
// Constructor
// ============================================================

SimpleFileVaultBackend::SimpleFileVaultBackend(
    const std::filesystem::path& dir)
{
    // Ensure the directory exists before constructing the file path.
    // create_directories is a no-op if the directory already exists.
    std::filesystem::create_directories(dir);

    // The audit log is always named audit.log within the given directory.
    // This name is fixed so that read-back in the same session is reliable
    // without requiring any state about the active filename.
    path_ = dir / "audit.log";
}

// ============================================================
// append_line
// ============================================================

void SimpleFileVaultBackend::append_line(const std::string& line)
{
    // Open in append + binary mode. Binary mode ensures consistent
    // newline handling across platforms (no CRLF translation on Windows).
    std::ofstream out(path_, std::ios::app | std::ios::binary);

    if (!out) {
        throw std::runtime_error(
            "SimpleFileVaultBackend: failed to open audit log for append: " +
            path_.string());
    }

    // Write line followed by a newline delimiter.
    // Each call appends exactly one logical record.
    out << line << '\n';

    if (!out) {
        throw std::runtime_error(
            "SimpleFileVaultBackend: failed to write to audit log: " +
            path_.string());
    }

    // out is flushed and closed on destruction (RAII).
    // For fsync-level durability use FileVaultBackend with fsync_on_write=true.
}

// ============================================================
// read_last_line
// ============================================================

std::optional<std::string> SimpleFileVaultBackend::read_last_line()
{
    if (!std::filesystem::exists(path_)) {
        return std::nullopt;
    }

    std::ifstream in(path_, std::ios::in | std::ios::binary);
    if (!in) {
        return std::nullopt;
    }

    // Scan the full file on every call — no caching.
    // This ensures callers always see the authoritative on-disk state,
    // even if another process or thread has appended since last read.
    std::string line;
    std::string last;

    while (std::getline(in, line)) {
        // Strip trailing CR so Windows-written files read correctly on macOS/Linux
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            last = line;
        }
    }

    if (last.empty()) {
        return std::nullopt;
    }
    return last;
}

// ============================================================
// read_all
// ============================================================

std::vector<std::string> SimpleFileVaultBackend::read_all()
{
    std::vector<std::string> lines;

    if (!std::filesystem::exists(path_)) {
        return lines;
    }

    std::ifstream in(path_, std::ios::in | std::ios::binary);
    if (!in) {
        return lines;
    }

    // Scan the full file on every call — no caching.
    // Empty lines (e.g. from a trailing newline) are skipped so that
    // callers receive only meaningful audit records.
    std::string line;
    while (std::getline(in, line)) {
        // Strip trailing CR for cross-platform compatibility
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    return lines;
}

// ============================================================
// rotate
// ============================================================

void SimpleFileVaultBackend::rotate()
{
    // Trivial rotation: replace the audit log with an empty file.
    // No archival is performed. If archival is required, use
    // FileVaultBackend which moves the active file to an archive directory.
    //
    // Open with trunc | binary to atomically zero the file.
    // Any subsequent append_line() calls start a fresh log.
    std::ofstream out(path_,
                      std::ios::out |
                      std::ios::trunc |
                      std::ios::binary);

    if (!out) {
        throw std::runtime_error(
            "SimpleFileVaultBackend: failed to truncate audit log on rotate: " +
            path_.string());
    }

    // out is closed on destruction — file is now empty and ready for writes.
}

} // namespace uml001