/**
 * @file main_ntp.cpp
 * @brief Production-grade Aegis BFT trusted clock daemon with CLI flags and test-safe defaults.
 */

#include "uml001/strong_clock.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/vault.h"
#include "uml001/crypto_utils.h"
#include "uml001/vault_logger.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/governor.h"

#include <grpcpp/grpcpp.h>
#include "clock_service.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <thread>
#include <unordered_set>
#include <memory>

namespace fs = std::filesystem;

// ============================================================
// CLI CONFIG
// ============================================================

struct Config {
    std::string data_dir = "./data";
    std::string grpc_addr = "0.0.0.0:50051";
    bool insecure_dev = false;
};

Config parse_args(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--data-dir" && i + 1 < argc) {
            cfg.data_dir = argv[++i];
        } else if (arg == "--grpc-addr" && i + 1 < argc) {
            cfg.grpc_addr = argv[++i];
        } else if (arg == "--insecure-dev") {
            cfg.insecure_dev = true;
        }
    }
    return cfg;
}

// ============================================================
// SIGNAL HANDLING
// ============================================================

std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true);
}

// ============================================================
// MAIN
// ============================================================

int main(int argc, char** argv) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto cfg = parse_args(argc, argv);
    fs::path data_dir_path = cfg.data_dir;

    std::cout << "[INIT] Starting Aegis Clock\n";
    std::cout << "[INIT] Data dir: " << data_dir_path.string() << "\n";

    try {
        fs::create_directories(data_dir_path);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Failed to create data dir: " << e.what() << "\n";
        return 1;
    }

    // Core components
    uml001::OsStrongClock strong_clock;
    uml001::SimpleHashProvider hash_provider;

    // Vault setup
    uml001::ColdVault::Config vault_cfg;
    vault_cfg.base_directory = data_dir_path;

    auto backend = std::make_shared<uml001::SimpleFileVaultBackend>(data_dir_path / "vault.log");
    auto vault_ptr = std::make_shared<uml001::ColdVault>(vault_cfg, backend, strong_clock, hash_provider);

    uml001::set_vault_logger([vault_ptr](const std::string& k, const std::string& v) {
        vault_ptr->log_security_event(k, v);
    });

    std::unordered_set<std::string> authorities = {
        "time.cloudflare.com",
        "time.google.com",
        "time.nist.gov"
    };

    uml001::BftClockConfig cfg_bft;
    cfg_bft.min_quorum = 3;
    cfg_bft.fail_closed = !cfg.insecure_dev;

    uml001::BFTQuorumTrustedClock clock(cfg_bft, authorities, vault_ptr);

    std::vector<uml001::NtpServerEntry> servers = {
        { "time.cloudflare.com", 1000, 2000 },
        { "time.google.com",     1000, 2000 },
        { "time.nist.gov",       1000, 2000 }
    };

    uml001::NtpObservationFetcher fetcher("", "", servers, 3, 15, 5);
    uml001::ClockGovernor governor(5);

    // ========================================================
    // gRPC SERVER
    // ========================================================

    class ServiceImpl final : public uml001::ClockService::Service {
    public:
        explicit ServiceImpl(uml001::OsStrongClock& clock) : clock_(clock) {}
        grpc::Status GetTime(grpc::ServerContext*,
                             const uml001::GetTimeRequest*,
                             uml001::TimeResponse* resp) override
        {
            resp->set_unix_timestamp(clock_.now_unix());
            return grpc::Status::OK;
        }
    private:
        uml001::OsStrongClock& clock_;
    };

    ServiceImpl service(strong_clock);
    grpc::ServerBuilder builder;
    builder.AddListeningPort(cfg.grpc_addr, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();
    std::cout << "[RPC] Listening on " << cfg.grpc_addr << "\n";

    // ========================================================
    // BACKGROUND THREAD
    // ========================================================

    std::thread worker([&]() {
        while (!g_shutdown.load()) {
            try {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto obs = fetcher.fetch();
                clock.update_and_sync(obs, 0.0);
            } catch (...) {
                uml001::vault_log("error", "background loop failure");
            }
        }
    });

    // ========================================================
    // WAIT LOOP
    // ========================================================

    while (!g_shutdown.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "[SHUTDOWN]\n";
    server->Shutdown();
    worker.join();

    return 0;
}