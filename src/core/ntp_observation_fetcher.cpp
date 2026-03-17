// ntp_observation_fetcher.cpp
/**
 * @file ntp_observation_fetcher.cpp
 * @brief Implementation of the Byzantine-resilient NTP observation fetcher.
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
#include <sstream>
#include <thread>
#include <iomanip>

namespace uml001 {

// ============================================================
// Module-level constants
// ============================================================

static constexpr uint64_t NTP_UNIX_OFFSET       = 2'208'988'800ULL;
static constexpr size_t   NTP_PACKET_SIZE       = 48;
static constexpr uint8_t  NTP_CLIENT_BYTE0      = 0x23;
static constexpr size_t   NTP_STRATUM_OFFSET    = 1;
static constexpr size_t   NTP_TRANSMIT_TS_OFFSET = 40;
static constexpr uint32_t DEFAULT_TIMEOUT_MS    = 2000;

// ============================================================
// RAII helpers
// ============================================================

struct AddrInfoDeleter {
    void operator()(addrinfo* p) const noexcept {
        if (p) freeaddrinfo(p);
    }
};

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

    SocketGuard(const SocketGuard&)            = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;

    SocketGuard(SocketGuard&& other) noexcept
        : fd_(other.release()) {}

    SocketGuard& operator=(SocketGuard&& other) noexcept {
        if (this != &other) {
            if (fd_ != kInvalid) close_fd(fd_);
            fd_ = other.release();
        }
        return *this;
    }

    fd_t fd()    const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ != kInvalid; }

    fd_t release() noexcept {
        fd_t tmp = fd_;
        fd_ = kInvalid;
        return tmp;
    }

private:
    fd_t fd_;
};

static bool sockaddr_equal(
    const sockaddr* expected,
    const sockaddr* received,
    socklen_t       received_len
) noexcept {
    if (!expected || !received) return false;
    if (expected->sa_family != received->sa_family) return false;

    if (expected->sa_family == AF_INET) {
        if (received_len < static_cast<socklen_t>(sizeof(sockaddr_in)))
            return false;
        const auto* a = reinterpret_cast<const sockaddr_in*>(expected);
        const auto* b = reinterpret_cast<const sockaddr_in*>(received);
        return (a->sin_addr.s_addr == b->sin_addr.s_addr) &&
               (a->sin_port        == b->sin_port);
    }

    if (expected->sa_family == AF_INET6) {
        if (received_len < static_cast<socklen_t>(sizeof(sockaddr_in6)))
            return false;
        const auto* a = reinterpret_cast<const sockaddr_in6*>(expected);
        const auto* b = reinterpret_cast<const sockaddr_in6*>(received);
        return (std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0) &&
               (a->sin6_port == b->sin6_port);
    }

    return false;
}

// ============================================================
// Constructor / Destructor
// ============================================================

NtpObservationFetcher::NtpObservationFetcher(
    std::string                 hmac_key,
    std::string                 key_id,
    std::vector<NtpServerEntry> servers,
    uint8_t                     stratum_max,
    size_t                      quorum_size,
    uint64_t                    outlier_threshold_s
)
    : hmac_key_(std::move(hmac_key))
    , key_id_(std::move(key_id))
    , servers_(std::move(servers))
    , stratum_max_(stratum_max)
    , quorum_size_(quorum_size)
    , outlier_threshold_s_(outlier_threshold_s)
{
    for (const auto& s : servers_) {
        sequences_[s.hostname] = 0;
    }
}

NtpObservationFetcher::~NtpObservationFetcher() = default;

// ============================================================
// Public API
// ============================================================

std::vector<TimeObservation>
NtpObservationFetcher::fetch()
{
    std::vector<std::future<std::optional<NtpObservation>>> futures;
    futures.reserve(servers_.size());

    for (const auto& server : servers_) {
        futures.push_back(
            std::async(
                std::launch::async,
                &NtpObservationFetcher::query_server,
                this,
                server
            )
        );
    }

    std::vector<NtpObservation> raw;
    raw.reserve(servers_.size());

    for (auto& fut : futures) {
        try {
            auto r = fut.get();
            if (r) raw.push_back(std::move(*r));
        } catch (const std::exception& ex) {
            vault_log("ntp.fetch.exception", ex.what());
        } catch (...) {
            vault_log("ntp.fetch.exception", "unknown");
        }
    }

    if (raw.empty()) {
        vault_log("ntp.fetch.no_responses", "all servers failed or timed out");
        return {};
    }

    std::vector<uint64_t> times;
    times.reserve(raw.size());
    for (const auto& r : raw)
        times.push_back(r.unix_seconds);

    std::vector<NtpObservation> filtered;
    filtered.reserve(raw.size());

    for (auto& r : raw) {
        if (!is_byzantine_outlier(r.unix_seconds, times)) {
            filtered.push_back(r);
        } else {
            r.is_outlier = true;
            vault_log("ntp.outlier.rejected", r.server_hostname);
        }
    }

    if (filtered.empty()) {
        vault_log("ntp.fetch.all_outliers", "no observations survived filtering");
        return {};
    }

    std::vector<TimeObservation> signed_obs;
    signed_obs.reserve(filtered.size());

    for (const auto& r : filtered) {
        signed_obs.push_back(sign_observation(r));
    }

    auto token = build_quorum_token(filtered);
    if (token) {
        vault_log("ntp.quorum.timestamp", std::to_string(token->unix_time));
    } else {
        vault_log("ntp.quorum.insufficient",
                  "filtered=" + std::to_string(filtered.size()) +
                  " required=" + std::to_string(quorum_size_));
    }

    return signed_obs;
}

void NtpObservationFetcher::set_hmac_key(std::string new_hmac_key,
                                         std::string new_key_id)
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    hmac_key_ = std::move(new_hmac_key);
    key_id_   = std::move(new_key_id);
}

std::string NtpObservationFetcher::save_sequence_state() const
{
    std::lock_guard<std::mutex> lock(seq_mutex_);
    std::ostringstream oss;
    for (const auto& kv : sequences_) {
        oss << kv.first << "=" << kv.second << "\n";
    }
    return oss.str();
}

// ============================================================
// query_server
// ============================================================

std::optional<NtpObservation>
NtpObservationFetcher::query_server(const NtpServerEntry& server) const
{
    struct addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family   = AF_UNSPEC;

    addrinfo* raw_res = nullptr;
    if (getaddrinfo(server.hostname.c_str(), "123", &hints, &raw_res) != 0) {
        vault_log("ntp.getaddrinfo.failed", server.hostname);
        return std::nullopt;
    }
    std::unique_ptr<addrinfo, AddrInfoDeleter> res(raw_res);

    SocketGuard sock(
        static_cast<SocketGuard::fd_t>(
            socket(res->ai_family, res->ai_socktype, res->ai_protocol)
        )
    );

    if (!sock.valid()) {
        vault_log("ntp.socket.failed", server.hostname);
        return std::nullopt;
    }

    const uint32_t timeout_ms =
        server.timeout_ms ? server.timeout_ms : DEFAULT_TIMEOUT_MS;

#ifdef _WIN32
    DWORD tv_win = static_cast<DWORD>(timeout_ms);
    setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&tv_win), sizeof(tv_win));
#else
    struct timeval tv{};
    tv.tv_sec  = static_cast<time_t>(timeout_ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    setsockopt(sock.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    uint8_t packet[NTP_PACKET_SIZE] = {};
    packet[0] = NTP_CLIENT_BYTE0;

    auto t1 = std::chrono::steady_clock::now();

    const ssize_t sent = sendto(
        sock.fd(),
        reinterpret_cast<const char*>(packet),
        NTP_PACKET_SIZE,
        0,
        res->ai_addr,
        res->ai_addrlen
    );

    if (sent != static_cast<ssize_t>(NTP_PACKET_SIZE)) {
        vault_log("ntp.sendto.failed", server.hostname);
        return std::nullopt;
    }

    uint8_t         response[NTP_PACKET_SIZE] = {};
    sockaddr_storage src_addr{};
    socklen_t        src_len = sizeof(src_addr);

    const ssize_t recvd = recvfrom(
        sock.fd(),
        reinterpret_cast<char*>(response),
        NTP_PACKET_SIZE,
        0,
        reinterpret_cast<sockaddr*>(&src_addr),
        &src_len
    );

    auto t4 = std::chrono::steady_clock::now();

    if (recvd != static_cast<ssize_t>(NTP_PACKET_SIZE)) {
        vault_log("ntp.recv.failed", server.hostname);
        return std::nullopt;
    }

    if (!sockaddr_equal(
            res->ai_addr,
            reinterpret_cast<const sockaddr*>(&src_addr),
            src_len))
    {
        vault_log("ntp.src.mismatch", server.hostname);
        return std::nullopt;
    }

    const uint8_t li_vn_mode = response[0];
    const uint8_t mode       = li_vn_mode & 0x07u;
    const uint8_t version    = (li_vn_mode >> 3) & 0x07u;

    if (mode != 4 && mode != 5) {
        vault_log("ntp.invalid.mode",
                  server.hostname + "|" + std::to_string(mode));
        return std::nullopt;
    }

    if (version < 3 || version > 4) {
        vault_log("ntp.invalid.version",
                  server.hostname + "|" + std::to_string(version));
        return std::nullopt;
    }

    uint64_t rtt_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t1).count()
    );

    if (rtt_ms > server.max_rtt_ms) {
        vault_log("ntp.rtt.too_high",
                  server.hostname + "|" + std::to_string(rtt_ms) + "ms");
        return std::nullopt;
    }

    const uint8_t stratum = response[NTP_STRATUM_OFFSET];
    if (stratum == 0 || stratum > stratum_max_) {
        vault_log("ntp.stratum.rejected",
                  server.hostname + "|" + std::to_string(stratum));
        return std::nullopt;
    }

    uint32_t ntp_seconds_be = 0;
    std::memcpy(&ntp_seconds_be, response + NTP_TRANSMIT_TS_OFFSET,
                sizeof(uint32_t));
    const uint32_t ntp_seconds = ntohl(ntp_seconds_be);

    if (static_cast<uint64_t>(ntp_seconds) < NTP_UNIX_OFFSET) {
        vault_log("ntp.time.before_epoch", server.hostname);
        return std::nullopt;
    }

    const uint64_t unix_time =
        static_cast<uint64_t>(ntp_seconds) - NTP_UNIX_OFFSET;

    const int64_t correction =
        static_cast<int64_t>(rtt_ms) / 2000;

    const int64_t corrected =
        static_cast<int64_t>(unix_time) - correction;

    if (corrected <= 0) {
        vault_log("ntp.corrected.negative", server.hostname);
        return std::nullopt;
    }

    return NtpObservation{
        server.hostname,
        static_cast<uint64_t>(corrected),
        rtt_ms,
        stratum,
        false
    };
}

// ============================================================
// sign_observation
// ============================================================

TimeObservation
NtpObservationFetcher::sign_observation(const NtpObservation& raw)
{
    uint64_t seq = 0;
    std::string key_id_copy;
    std::string hmac_key_copy;

    {
        std::lock_guard<std::mutex> lock(seq_mutex_);
        auto it = sequences_.find(raw.server_hostname);
        if (it == sequences_.end()) {
            sequences_[raw.server_hostname] = 0;
            it = sequences_.find(raw.server_hostname);
        }
        it->second += 1;
        seq = it->second;
        key_id_copy  = key_id_;
        hmac_key_copy = hmac_key_;
    }

    std::ostringstream payload_oss;
    payload_oss << raw.server_hostname << "|"
                << key_id_copy << "|"
                << raw.unix_seconds << "|"
                << seq;
    const std::string payload = payload_oss.str();

    std::vector<uint8_t> key_bytes(
        hmac_key_copy.begin(), hmac_key_copy.end());

    unsigned int mac_len = 0;
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) throw std::runtime_error("HMAC_CTX_new failed");

    if (HMAC_Init_ex(ctx, key_bytes.data(),
                     static_cast<int>(key_bytes.size()),
                     EVP_sha256(), nullptr) != 1)
    {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Init_ex failed");
    }

    if (HMAC_Update(ctx,
                    reinterpret_cast<const unsigned char*>(payload.data()),
                    payload.size()) != 1)
    {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Update failed");
    }

    if (HMAC_Final(ctx, mac.data(), &mac_len) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Final failed");
    }

    HMAC_CTX_free(ctx);
    mac.resize(mac_len);

    std::ostringstream sig_oss;
    for (uint8_t b : mac) {
        sig_oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
    }

    vault_log("ntp.observation.signed", raw.server_hostname);

    return TimeObservation{
        raw.server_hostname,
        key_id_copy,
        raw.unix_seconds,
        sig_oss.str(),
        seq
    };
}

// ============================================================
// Outlier filtering helpers
// ============================================================

bool NtpObservationFetcher::is_byzantine_outlier(
    uint64_t                     value,
    const std::vector<uint64_t>& values
) const
{
    if (values.empty() || outlier_threshold_s_ == 0)
        return false;

    uint64_t med = median(values);
    uint64_t diff = (value > med) ? (value - med) : (med - value);
    return diff > outlier_threshold_s_;
}

uint64_t NtpObservationFetcher::median(std::vector<uint64_t> values) const
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t n = values.size();
    if (n % 2 == 1) {
        return values[n / 2];
    }
    uint64_t a = values[(n / 2) - 1];
    uint64_t b = values[n / 2];
    return (a + b) / 2;
}

// ============================================================
// Drift estimator
// ============================================================

uint64_t NtpObservationFetcher::estimate_drift(uint64_t new_time)
{
    using clock = std::chrono::system_clock;

    const uint64_t local_now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            clock::now().time_since_epoch()).count()
    );

    std::lock_guard<std::mutex> lock(drift_mutex_);

    if (last_reference_time_ == 0 || last_local_time_ == 0) {
        last_reference_time_ = new_time;
        last_local_time_     = local_now;
        return 0;
    }

    int64_t delta_ref   = static_cast<int64_t>(new_time) -
                          static_cast<int64_t>(last_reference_time_);
    int64_t delta_local = static_cast<int64_t>(local_now) -
                          static_cast<int64_t>(last_local_time_);

    if (delta_ref <= 0) {
        vault_log("ntp.drift.backward_reference", "");
        last_reference_time_ = new_time;
        last_local_time_     = local_now;
        return 0;
    }

    if (delta_local <= 0) {
        vault_log("ntp.drift.backward_local", "");
        last_reference_time_ = new_time;
        last_local_time_     = local_now;
        return 0;
    }

    last_reference_time_ = new_time;
    last_local_time_     = local_now;

    double ref_d   = static_cast<double>(delta_ref);
    double local_d = static_cast<double>(delta_local);

    double ppm = ((ref_d - local_d) / local_d) * 1'000'000.0;
    if (ppm < 0) ppm = -ppm;
    return static_cast<uint64_t>(ppm);
}

// ============================================================
// Quorum token
// ============================================================

std::optional<TimestampAttestationToken>
NtpObservationFetcher::build_quorum_token(const std::vector<NtpObservation>& obs)
{
    if (obs.size() < quorum_size_)
        return std::nullopt;

    std::vector<uint64_t> times;
    std::vector<uint64_t> rtts;
    times.reserve(obs.size());
    rtts.reserve(obs.size());

    for (const auto& o : obs) {
        times.push_back(o.unix_seconds);
        rtts.push_back(o.rtt_ms);
    }

    uint64_t med_time = median(times);
    uint64_t med_rtt  = median(rtts);
    uint64_t drift_ppm = estimate_drift(med_time);

    std::vector<std::string> servers;
    servers.reserve(obs.size());
    for (const auto& o : obs)
        servers.push_back(o.server_hostname);

    std::sort(servers.begin(), servers.end());

    std::string concat;
    for (const auto& s : servers)
        concat += s;

    std::string quorum_hash = sha256_hex(concat);

    std::ostringstream payload_oss;
    payload_oss << med_time << "|" << quorum_hash << "|" << drift_ppm;
    const std::string payload = payload_oss.str();

    std::vector<uint8_t> key_bytes(
        hmac_key_.begin(), hmac_key_.end());

    unsigned int mac_len = 0;
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) throw std::runtime_error("HMAC_CTX_new failed");

    if (HMAC_Init_ex(ctx, key_bytes.data(),
                     static_cast<int>(key_bytes.size()),
                     EVP_sha256(), nullptr) != 1)
    {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Init_ex failed");
    }

    if (HMAC_Update(ctx,
                    reinterpret_cast<const unsigned char*>(payload.data()),
                    payload.size()) != 1)
    {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Update failed");
    }

    if (HMAC_Final(ctx, mac.data(), &mac_len) != 1) {
        HMAC_CTX_free(ctx);
        throw std::runtime_error("HMAC_Final failed");
    }

    HMAC_CTX_free(ctx);
    mac.resize(mac_len);

    std::ostringstream sig_oss;
    for (uint8_t b : mac) {
        sig_oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(b);
    }

    vault_log("ntp.tat.generated", std::to_string(med_time));

    TimestampAttestationToken token{
        med_time,
        med_rtt,
        drift_ppm,
        servers,
        quorum_hash,
        sig_oss.str()
    };

    return token;
}

} // namespace uml001