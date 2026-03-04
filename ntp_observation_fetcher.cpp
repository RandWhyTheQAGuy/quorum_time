#include "ntp_observation_fetcher.h"
#include "crypto_utils.h"

#ifdef _WIN32
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include <thread>
#include <future>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <iostream>

namespace uml001 {

static constexpr uint64_t NTP_UNIX_OFFSET = 2208988800ULL;
static constexpr size_t NTP_PACKET_SIZE = 48;
static constexpr uint8_t NTP_CLIENT_BYTE0 = 0x23;
static constexpr size_t NTP_TRANSMIT_TS_OFFSET = 40;
static constexpr size_t NTP_STRATUM_OFFSET = 1;

NtpObservationFetcher::NtpObservationFetcher(
    std::string hmac_key,
    std::vector<NtpServerEntry> servers,
    uint8_t stratum_max)
    : hmac_key_(std::move(hmac_key))
    , servers_(std::move(servers))
    , stratum_max_(stratum_max)
{
    if (hmac_key_.empty() || servers_.empty())
        throw std::invalid_argument("Invalid initialization parameters");

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif

    for (const auto& s : servers_) sequences_[s.hostname] = 0;
}

NtpObservationFetcher::~NtpObservationFetcher() {
#ifdef _WIN32
    WSACleanup();
#endif
}

std::vector<TimeObservation> NtpObservationFetcher::fetch() {
    std::vector<std::future<std::optional<NtpObservation>>> futures;
    for (const auto& server : servers_) {
        futures.push_back(std::async(std::launch::async, &NtpObservationFetcher::query_server, this, std::cref(server)));
    }

    std::vector<TimeObservation> observations;
    for (size_t i = 0; i < futures.size(); ++i) {
        try {
            auto result = futures[i].get();
            if (result.has_value()) {
                observations.push_back(sign_observation(*result));
            }
        } catch (...) { /* Handle silent drop */ }
    }
    return observations;
}

std::optional<NtpObservation> NtpObservationFetcher::query_server(const NtpServerEntry& server) const {
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* res = nullptr;
    if (getaddrinfo(server.hostname.c_str(), std::to_string(server.port).c_str(), &hints, &res) != 0) {
        return std::nullopt;
    }

    struct AddrInfoGuard {
        struct addrinfo* p;
        ~AddrInfoGuard() { freeaddrinfo(p); }
    } guard{res};

    socket_t sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) return std::nullopt;

    struct SockGuard {
        socket_t fd;
        ~SockGuard() { 
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd); 
#endif
        }
    } sg{sock};

#ifdef _WIN32
    DWORD timeout = server.timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv{};
    tv.tv_sec  = server.timeout_ms / 1000;
    tv.tv_usec = (server.timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    uint8_t packet[NTP_PACKET_SIZE] = {0};
    packet[0] = NTP_CLIENT_BYTE0;

    auto t1 = std::chrono::steady_clock::now();
    ssize_t_compat sent = sendto(sock, (const char*)packet, NTP_PACKET_SIZE, 0, res->ai_addr, (int)res->ai_addrlen);
    if (sent != NTP_PACKET_SIZE) return std::nullopt;

    uint8_t response[NTP_PACKET_SIZE] = {0};
    ssize_t_compat received = recvfrom(sock, (char*)response, NTP_PACKET_SIZE, 0, nullptr, nullptr);
    if (received < NTP_PACKET_SIZE) return std::nullopt;

    auto t4 = std::chrono::steady_clock::now();
    uint8_t stratum = response[NTP_STRATUM_OFFSET];

    // STRATUM-2/RELAY CONFIRMATION:
    // This allows anything up to stratum_max_ (default 3), strictly handling relay servers natively.
    if (stratum == 0 || stratum > stratum_max_) return std::nullopt;

    uint32_t ntp_seconds_be;
    std::memcpy(&ntp_seconds_be, response + NTP_TRANSMIT_TS_OFFSET, sizeof(uint32_t));
    uint32_t ntp_seconds = ntohl(ntp_seconds_be);

    if (ntp_seconds < NTP_UNIX_OFFSET) return std::nullopt;
    uint64_t server_unix = static_cast<uint64_t>(ntp_seconds) - NTP_UNIX_OFFSET;

    uint64_t rtt_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t1).count();
    if (rtt_ms > server.max_rtt_ms) return std::nullopt;

    uint64_t corrected_unix = server_unix;
    if (rtt_ms >= 2000) {
        corrected_unix = (server_unix > rtt_ms / 2000) ? server_unix - (rtt_ms / 2000) : 0;
    }

    return NtpObservation{ server.hostname, corrected_unix, rtt_ms, stratum, false };
}

TimeObservation NtpObservationFetcher::sign_observation(const NtpObservation& raw) {
    uint64_t seq;
    {
        std::lock_guard<std::mutex> lock(seq_mutex_);
        seq = ++sequences_[raw.server_hostname];
    }
    std::string payload = raw.server_hostname + "|" + std::to_string(raw.unix_seconds) + "|" + std::to_string(seq);
    std::string signature = hmac_sha256_hex(payload, hmac_key_);

    return TimeObservation{ raw.server_hostname, raw.unix_seconds, signature, seq };
}

void NtpObservationFetcher::load_sequence_state(const std::unordered_map<std::string, uint64_t>& state) {
    std::lock_guard<std::mutex> lock(seq_mutex_);
    for (const auto& [hostname, seq] : state) {
        if (sequences_.count(hostname)) sequences_[hostname] = seq;
    }
}

std::unordered_map<std::string, uint64_t> NtpObservationFetcher::save_sequence_state() const {
    std::lock_guard<std::mutex> lock(seq_mutex_);
    return sequences_;
}

} // namespace uml001