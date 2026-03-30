/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine‑resilient trusted‑time
 * system designed for modern distributed environments. It provides a
 * cryptographically anchored notion of time that can be aligned,
 * audited, and shared across domains without requiring centralized
 * trust.
 *
 * This project also includes the Aegis Semantic Passport components,
 * which complement Quorum Time by offering structured, verifiable
 * identity and capability attestations for agents and services.
 *
 * Core capabilities:
 *   - BFT Quorum Time: multi‑authority, tamper‑evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross‑domain alignment (AlignTime).
 *
 *   - Transparency Logging: append‑only, hash‑chained audit records
 *                           for time events, alignment proofs, and
 *                           key‑rotation operations.
 *
 *   - Semantic Passports: optional identity and capability metadata
 *                         for systems that require verifiable agent
 *                         provenance and authorization context.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security‑critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open‑source project with a focus on
 * clarity, auditability, and long‑term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community‑driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/file_vault_backend.h"

#include <stdexcept>
#include <fstream>

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
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

void FileVaultBackend::open_new_file() {
    const uint64_t ts = strong_clock_.now_unix();

    active_file_ = base_dir_ / ("vault_" + std::to_string(ts) + ".log");

    stream_.open(active_file_, std::ios::app | std::ios::binary);
    if (!stream_) {
        throw std::runtime_error("Failed to open vault file: " + active_file_.string());
    }
}

void FileVaultBackend::append_line(const std::string& line) {
    if (!stream_) {
        throw std::runtime_error("append_line called on closed vault stream");
    }

    stream_ << line;
    stream_.flush();

    if (!stream_) {
        throw std::runtime_error("Failed to write to vault file: " + active_file_.string());
    }

    if (fsync_on_write_) {
#ifdef _WIN32
        int fd = open_fd(active_file_.string().c_str(), _O_WRONLY | _O_APPEND | _O_BINARY, _S_IREAD | _S_IWRITE);
#else
        int fd = open_fd(active_file_.c_str(), O_WRONLY | O_APPEND);
#endif
        if (fd < 0) {
            throw std::runtime_error("Failed to open file descriptor for fsync: " + active_file_.string());
        }

        if (fsync(fd) != 0) {
            close_fd(fd);
            throw std::runtime_error("fsync failed for vault file: " + active_file_.string());
        }

        close_fd(fd);
    }
}

std::optional<std::string> FileVaultBackend::read_last_line() {
    if (!std::filesystem::exists(active_file_)) return std::nullopt;

    std::ifstream in(active_file_, std::ios::in | std::ios::binary);
    if (!in) return std::nullopt;

    std::string line, last;
    while (std::getline(in, line)) {
        last = line;
    }

    if (last.empty()) return std::nullopt;
    return last;
}

void FileVaultBackend::archive_current() {
    if (stream_.is_open()) {
        stream_.flush();
        stream_.close();
    }

    const auto archive_dir = base_dir_ / "archive";
    std::filesystem::create_directories(archive_dir);

    auto new_path = archive_dir / active_file_.filename();
    if (std::filesystem::exists(new_path)) {
        const auto ts = strong_clock_.now_unix();
        new_path = archive_dir / ("vault_" + std::to_string(ts) + "_archived.log");
        if (std::filesystem::exists(new_path)) {
            throw std::runtime_error("Refusing to overwrite archived vault file: " + new_path.string());
        }
    }
    std::filesystem::rename(active_file_, new_path);
}

void FileVaultBackend::rotate() {
    archive_current();
    open_new_file();
}

} // namespace uml001