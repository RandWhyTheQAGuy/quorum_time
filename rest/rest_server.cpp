#include <pistache/endpoint.h>
#include <pistache/router.h>

#include <unordered_set>
#include <optional>
#include <filesystem>
#include <ctime>
#include <memory>
#include <string>

#include "uml001/bft_quorum_clock.h"
#include "uml001/rest_handlers.h"
#include "uml001/rest_auth_config.h"
#include "uml001/vault.h"
#include "uml001/strong_clock.h"
#include "uml001/hash_provider.h"

using namespace uml001;
using namespace uml001::rest;

// ------------------------------------------------------------
// Dummy implementations for testing / REST server bring-up
// ------------------------------------------------------------

// Minimal strong clock for ColdVault + BFT clock
class DummyStrongClock : public IStrongClock {
public:
    std::uint64_t now_unix() const override {
        return static_cast<std::uint64_t>(std::time(nullptr));
    }

    std::int64_t get_current_drift() const override {
        return 0;
    }
};

// Minimal hash provider for ColdVault
class DummyHashProvider : public IHashProvider {
public:
    std::string sha256(const std::string& input) override {
        // Deterministic, trivial hash for testing
        return "dummy_" + input;
    }
};

// Minimal backend that satisfies IVaultBackend
class DummyVaultBackend : public IVaultBackend {
public:
    void append_line(const std::string&) override {
        // No-op
    }

    std::optional<std::string> read_last_line() override {
        return std::nullopt;
    }

    void rotate() override {
        // No-op
    }
};

int main() {
    // --------------------------------------------------------
    // HTTP server setup
    // --------------------------------------------------------
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(8080));

    auto opts = Pistache::Http::Endpoint::options()
        .threads(2)
        .flags(Pistache::Tcp::Options::ReuseAddr);

    Pistache::Http::Endpoint server(addr);
    server.init(opts);

    Pistache::Rest::Router router;

    // --------------------------------------------------------
    // Clock + Vault wiring
    // --------------------------------------------------------

    BftClockConfig cfg;
    std::unordered_set<std::string> authorities = {"pool.ntp.org"};

    // Dummy clock + hash provider
    DummyStrongClock strong_clock;
    DummyHashProvider hash_provider;

    // Dummy vault backend
    auto backend = std::make_unique<DummyVaultBackend>();

    // ColdVault configuration
    ColdVault::Config vault_cfg;
    vault_cfg.base_directory = std::filesystem::path("/tmp/uml001_dummy_vault");
    vault_cfg.max_file_size_bytes = 10 * 1024 * 1024; // 10MB
    vault_cfg.max_file_age_seconds = 86400;           // 24h
    vault_cfg.fsync_on_write = false;

    // Construct the ColdVault
    ColdVault vault(vault_cfg, std::move(backend), strong_clock, hash_provider);

    // BFT quorum clock using the dummy vault
    auto clock = std::make_shared<BFTQuorumTrustedClock>(
        cfg,
        authorities,
        vault
    );

    // --------------------------------------------------------
    // REST auth + handlers
    // --------------------------------------------------------
    RestAuthConfig auth;
    auth.mode = RestAuthMode::API_KEY;
    auth.api_key = "supersecret";

    TimeApiHandler handler(clock, auth, vault);
    handler.setup_routes(router);

    server.setHandler(router.handler());
    server.serve();

    return 0;
}
