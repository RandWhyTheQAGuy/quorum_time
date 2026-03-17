#include <pistache/endpoint.h>
#include <pistache/router.h>

#include "uml001/bft_quorum_clock.h"
#include "uml001/rest_handlers.h"
#include "uml001/rest_auth_config.h"

using namespace uml001;
using namespace uml001::rest;

int main() {
    Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(8080));

    auto opts = Pistache::Http::Endpoint::options()
        .threads(2)
        .flags(Pistache::Tcp::Options::ReuseAddr);

    Pistache::Http::Endpoint server(addr);
    server.init(opts);

    Pistache::Rest::Router router;

    // Example: load config + vault + authorities
    BftClockConfig cfg;
    std::unordered_set<std::string> authorities = {"pool.ntp.org"};

    // Replace with real vault
    class DummyVault : public ColdVault {
        std::optional<int64_t> load_last_drift() override { return 0; }
        std::unordered_map<std::string,uint64_t> load_authority_sequences() override { return {}; }
        void save_authority_sequences(const std::unordered_map<std::string,uint64_t>&) override {}
        void log_sync_event(uint64_t, int64_t, int64_t) override {}
        void log_security_event(const std::string&, const std::string&) override {}
    } vault;

    auto clock = std::make_shared<BFTQuorumTrustedClock>(
        cfg, authorities, vault
    );

    RestAuthConfig auth;
    auth.mode = RestAuthMode::API_KEY;
    auth.api_key = "supersecret";

    TimeApiHandler handler(clock, auth, vault);
    handler.setup_routes(router);

    server.setHandler(router.handler());
    server.serve();

    return 0;
}
