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
/**
 * @file ntp_observation_fetcher.cpp
 * @brief Hardened Byzantine-resilient NTP observation fetcher.
 */

#include "uml001/ntp_observation_fetcher.h"
#include "uml001/crypto_utils.h"
#include "uml001/vault_logger.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
   using ssize_t = int;
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace uml001 {

// ============================================================
// CONSTANTS
// ============================================================

static constexpr uint64_t NTP_UNIX_OFFSET        = 2208988800ULL;
static constexpr size_t   NTP_PACKET_SIZE        = 48;
static constexpr uint8_t  NTP_CLIENT_BYTE0       = 0x23;  // LI=0, VN=4, Mode=3
static constexpr size_t   NTP_STRATUM_OFFSET     = 1;
static constexpr size_t   NTP_TRANSMIT_TS_OFFSET = 40;
static constexpr uint32_t DEFAULT_TIMEOUT_MS     = 2000;

// ============================================================
// SOCKET RAII
// ============================================================

struct SocketGuard {
#ifdef _WIN32
    using fd_t = SOCKET;
    static constexpr fd_t kInvalid = INVALID_SOCKET;
    static void close_fd(fd_t f) noexcept { closesocket(f); }
#else
    using fd_t = int;
    static constexpr fd_t kInvalid = -1;
    static void close_fd(fd_t f) noexcept { ::close(f); }
#endif

    explicit SocketGuard(fd_t fd = kInvalid) noexcept : fd_(fd) {}
    ~SocketGuard() noexcept {
        if (fd_ != kInvalid) close_fd(fd_);
    }

    fd_t fd() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ != kInvalid; }

private:
    fd_t fd_;
};

// ============================================================
// CTOR
// ============================================================

NtpObservationFetcher::NtpObservationFetcher(
    const std::string& hmac_key,
    const std::string& key_id,
    const std::vector<NtpServerEntry>& servers,
    std::size_t quorum_size,
    std::uint32_t timeout_ms,
    std::uint32_t max_delay_ms
)
    : hmac_key_(hmac_key),
      key_id_(key_id),
      servers_(servers),
      quorum_size_(quorum_size),
      timeout_ms_(timeout_ms ? timeout_ms : DEFAULT_TIMEOUT_MS),
      max_delay_ms_(max_delay_ms),
      outlier_threshold_s_(5)
{
    for (const auto& s : servers_) {
        sequences_[s.hostname] = 0;
    }
}

// ============================================================
// PUBLIC API
// ============================================================

void NtpObservationFetcher::set_hmac_key(const std::string& new_hmac_key)
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    hmac_key_ = new_hmac_key;
}

std::size_t NtpObservationFetcher::get_active_authority_count() const
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    return sequences_.size();
}

std::string NtpObservationFetcher::save_sequence_state() const
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    std::ostringstream oss;
    bool first = true;
    for (const auto& kv : sequences_) {
        if (!first) {
            oss << ";";
        }
        first = false;
        oss << kv.first << ":" << kv.second;
    }
    return oss.str();
}

void NtpObservationFetcher::load_sequence_state(const std::string& state_data)
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    sequences_.clear();
    std::istringstream iss(state_data);
    std::string token;
    while (std::getline(iss, token, ';')) {
        if (token.empty()) continue;
        auto pos = token.find(':');
        if (pos == std::string::npos) continue;
        std::string host = token.substr(0, pos);
        std::string seq_str = token.substr(pos + 1);
        try {
            std::uint64_t seq = static_cast<std::uint64_t>(std::stoull(seq_str));
            sequences_[host] = seq;
        } catch (...) {
            // Ignore malformed entries
        }
    }
}

// ============================================================
// FETCH
// ============================================================

std::vector<TimeObservation>
NtpObservationFetcher::fetch()
{
    std::vector<std::future<std::optional<NtpObservation>>> futures;

    for (const auto& server : servers_) {
        futures.push_back(std::async(
            std::launch::async,
            &NtpObservationFetcher::query_server,
            this,
            server
        ));
    }

    std::vector<NtpObservation> raw;

    for (auto& f : futures) {
        try {
            auto r = f.get();
            if (r) raw.push_back(*r);
        } catch (...) {
            vault_log("ntp.fetch.exception", "async failure");
        }
    }

    if (raw.empty()) {
        return {};
    }

    std::vector<uint64_t> times;
    times.reserve(raw.size());
    for (auto& r : raw) times.push_back(r.unix_seconds);

    std::vector<NtpObservation> filtered;
    filtered.reserve(raw.size());
    for (auto& r : raw) {
        if (!is_byzantine_outlier(r.unix_seconds, times)) {
            filtered.push_back(r);
        }
    }

    std::vector<TimeObservation> out;
    out.reserve(filtered.size());
    for (auto& r : filtered) {
        out.push_back(sign_observation(r));
    }

    build_quorum_token(filtered);

    return out;
}

// ============================================================
// SIGNING
// ============================================================

TimeObservation
NtpObservationFetcher::sign_observation(const NtpObservation& raw)
{
    uint64_t seq;
    std::string key_id_copy;
    std::string hmac_key_copy;

    {
        std::lock_guard<std::mutex> lock(seq_mutex_);
        seq = ++sequences_[raw.server_hostname];
        key_id_copy = key_id_;
        hmac_key_copy = hmac_key_;
    }

    // Register RAW key (must match verifier)
    register_hmac_authority(
        raw.server_hostname,
        key_id_copy,
        hmac_key_copy
    );

    std::ostringstream payload;
    payload << raw.server_hostname << "|"
            << key_id_copy << "|"
            << raw.unix_seconds << "|"
            << seq;

    std::string payload_str = payload.str();

    unsigned int mac_len = 0;
    unsigned char* mac = HMAC(
        EVP_sha256(),
        hmac_key_copy.data(),
        static_cast<int>(hmac_key_copy.size()),
        reinterpret_cast<const unsigned char*>(payload_str.data()),
        payload_str.size(),
        nullptr,
        &mac_len
    );

    if (!mac || mac_len == 0) {
        throw std::runtime_error("HMAC failed");
    }

    std::ostringstream sig;
    for (unsigned int i = 0; i < mac_len; ++i) {
        sig << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }

    return TimeObservation{
        raw.server_hostname,
        key_id_copy,
        raw.unix_seconds,
        sig.str(),
        seq
    };
}

// ============================================================
// HELPERS
// ============================================================

bool NtpObservationFetcher::is_byzantine_outlier(
    uint64_t value,
    const std::vector<uint64_t>& values
) const
{
    if (values.size() < 3) return false;

    auto sorted = values;
    std::sort(sorted.begin(), sorted.end());

    uint64_t med = sorted[sorted.size() / 2];
    uint64_t diff = (value > med) ? (value - med) : (med - value);

    return diff > outlier_threshold_s_;
}

uint64_t NtpObservationFetcher::median(std::vector<uint64_t> v) const
{
    if (v.empty()) return 0;

    std::sort(v.begin(), v.end());
    size_t n = v.size();

    return (n % 2)
        ? v[n / 2]
        : (v[n/2 - 1] + v[n/2]) / 2;
}

std::uint64_t NtpObservationFetcher::estimate_drift(std::uint64_t /*new_time*/)
{
    // Placeholder for future drift estimation; tests currently do not rely on it.
    return 0;
}

// ============================================================
// TOKEN
// ============================================================

std::optional<TimestampAttestationToken>
NtpObservationFetcher::build_quorum_token(
    const std::vector<NtpObservation>& obs)
{
    if (obs.size() < quorum_size_) return std::nullopt;

    std::vector<uint64_t> times;
    std::vector<uint64_t> rtts;
    std::vector<std::string> hosts;

    times.reserve(obs.size());
    rtts.reserve(obs.size());
    hosts.reserve(obs.size());

    for (auto& o : obs) {
        times.push_back(o.unix_seconds);
        rtts.push_back(o.rtt_ms);
        hosts.push_back(o.server_hostname);
    }

    uint64_t med_time = median(times);
    std::string concat;

    std::sort(hosts.begin(), hosts.end());
    for (auto& h : hosts) concat += h;

    std::string q_hash = sha256_hex(concat);

    std::ostringstream payload;
    payload << med_time << "|" << q_hash;

    unsigned int mac_len = 0;
    unsigned char* mac = HMAC(
        EVP_sha256(),
        hmac_key_.data(),
        static_cast<int>(hmac_key_.size()),
        reinterpret_cast<const unsigned char*>(payload.str().data()),
        payload.str().size(),
        nullptr,
        &mac_len
    );

    if (!mac || mac_len == 0) return std::nullopt;

    std::ostringstream sig;
    for (unsigned int i = 0; i < mac_len; ++i) {
        sig << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }

    return TimestampAttestationToken{
        med_time,
        median(rtts),
        0,          // drift_ppm (not yet modeled here)
        hosts,
        q_hash,
        sig.str()
    };
}

// ============================================================
// NTP QUERY
// ============================================================

std::optional<NtpObservation>
NtpObservationFetcher::query_server(const NtpServerEntry& server) const
{
    // Resolve host
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* res = nullptr;
    int rc = ::getaddrinfo(server.hostname.c_str(), "123", &hints, &res);
    if (rc != 0 || !res) {
        vault_log("ntp.resolve.error", server.hostname);
        if (res) ::freeaddrinfo(res);
        return std::nullopt;
    }

    SocketGuard sock(::socket(res->ai_family, res->ai_socktype, res->ai_protocol));
    if (!sock.valid()) {
        vault_log("ntp.socket.error", server.hostname);
        ::freeaddrinfo(res);
        return std::nullopt;
    }

    // Timeout
    uint32_t effective_timeout = server.timeout_ms ? server.timeout_ms : timeout_ms_;
#ifdef _WIN32
    DWORD tv = effective_timeout;
    ::setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO,
                 reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec  = effective_timeout / 1000;
    tv.tv_usec = (effective_timeout % 1000) * 1000;
    ::setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // Build request
    std::uint8_t packet[NTP_PACKET_SIZE];
    std::memset(packet, 0, sizeof(packet));
    packet[0] = NTP_CLIENT_BYTE0;

    auto t1 = std::chrono::steady_clock::now();
    ssize_t sent = ::sendto(sock.fd(),
                            reinterpret_cast<const char*>(packet),
                            sizeof(packet),
                            0,
                            res->ai_addr,
                            res->ai_addrlen);
    if (sent != static_cast<ssize_t>(sizeof(packet))) {
        vault_log("ntp.send.error", server.hostname);
        ::freeaddrinfo(res);
        return std::nullopt;
    }

    std::uint8_t recv_buf[NTP_PACKET_SIZE];
    ssize_t recvd = ::recvfrom(sock.fd(),
                               reinterpret_cast<char*>(recv_buf),
                               sizeof(recv_buf),
                               0,
                               nullptr,
                               nullptr);
    auto t4 = std::chrono::steady_clock::now();
    ::freeaddrinfo(res);

    if (recvd < static_cast<ssize_t>(NTP_PACKET_SIZE)) {
        vault_log("ntp.recv.error", server.hostname);
        return std::nullopt;
    }

    // RTT
    auto rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t1).count();
    if (max_delay_ms_ && rtt_ms > static_cast<int64_t>(max_delay_ms_)) {
        vault_log("ntp.rtt.too_high", server.hostname);
        return std::nullopt;
    }

    // Stratum
    std::uint8_t stratum = recv_buf[NTP_STRATUM_OFFSET];

    // Transmit timestamp seconds
    std::uint32_t tx_secs_net;
    std::memcpy(&tx_secs_net, recv_buf + NTP_TRANSMIT_TS_OFFSET, sizeof(tx_secs_net));
    std::uint32_t tx_secs = ntohl(tx_secs_net);

    if (tx_secs < NTP_UNIX_OFFSET) {
        vault_log("ntp.timestamp.invalid", server.hostname);
        return std::nullopt;
    }

    std::uint64_t unix_secs = static_cast<std::uint64_t>(tx_secs - NTP_UNIX_OFFSET);

    NtpObservation obs;
    obs.server_hostname = server.hostname;
    obs.unix_seconds    = unix_secs;
    obs.rtt_ms          = static_cast<std::uint64_t>(rtt_ms < 0 ? 0 : rtt_ms);
    obs.stratum         = stratum;
    obs.is_outlier      = false;

    return obs;
}

} // namespace uml001
