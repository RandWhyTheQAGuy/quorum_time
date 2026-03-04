#pragma once

#include "bft_quorum_clock.h"
#include "crypto_utils.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <chrono>
#include <optional>
#include <cstdint>
#include <functional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
using ssize_t_compat = int;
#else
using socket_t = int;
using ssize_t_compat = ssize_t;
#define INVALID_SOCKET -1
#endif

namespace uml001 {

struct NtpServerEntry {
    std::string hostname;
    uint16_t    port       = 123;
    bool        nts_capable = false;
    uint32_t    timeout_ms = 2000;
    uint32_t    max_rtt_ms = 500;
};

struct NtpObservation {
    std::string server_hostname;
    uint64_t    unix_seconds;
    uint64_t    rtt_ms;
    uint8_t     stratum;
    bool        authenticated;
};

class NtpObservationFetcher {
public:
    static std::vector<NtpServerEntry> default_server_pool() {
        return {
            { "time.cloudflare.com", 123, true,  2000, 500 },
            { "time.google.com",     123, false, 2000, 500 },
            { "time.windows.com",    123, false, 2000, 500 },
            { "time.apple.com",      123, false, 2000, 500 },
            { "time.nist.gov",       123, false, 3000, 800 },
        };
    }

    // stratum_max defaults to 3, inherently supporting Stratum-1 and Stratum-2/Relay servers.
    explicit NtpObservationFetcher(
        std::string                  hmac_key,
        std::vector<NtpServerEntry>  servers     = default_server_pool(),
        uint8_t                      stratum_max = 3);

    ~NtpObservationFetcher();

    std::vector<TimeObservation> fetch();

    void load_sequence_state(const std::unordered_map<std::string, uint64_t>& state);
    std::unordered_map<std::string, uint64_t> save_sequence_state() const;

private:
    std::optional<NtpObservation> query_server(const NtpServerEntry& server) const;
    TimeObservation sign_observation(const NtpObservation& raw);

    std::string                    hmac_key_;
    std::vector<NtpServerEntry>    servers_;
    uint8_t                        stratum_max_;

    mutable std::mutex                              seq_mutex_;
    std::unordered_map<std::string, uint64_t>       sequences_;
};

} // namespace uml001