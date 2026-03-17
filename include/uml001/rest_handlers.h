#pragma once

#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include "bft_quorum_clock.h"
#include "rest_auth_config.h"

namespace uml001::rest {

/**
 * @brief REST handler for the UML-001 Trusted Time API.
 *
 * Endpoints:
 *   - GET  /time/now
 *   - POST /time/sync
 *   - POST /time/shared-state
 *
 * All endpoints enforce authentication and log:
 *   - Auth failures
 *   - Sync failures
 *   - Shared-state rejections
 *   - Successful operations
 */
class TimeApiHandler {
public:
    TimeApiHandler(
        std::shared_ptr<BFTQuorumTrustedClock> clock,
        RestAuthConfig                         auth_config,
        ColdVault&                             vault
    );

    void setup_routes(Pistache::Rest::Router& router);

private:
    bool check_auth(const Pistache::Rest::Request& req,
                    const std::string& endpoint_name,
                    std::string&       failure_reason);

    void handle_now(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    void handle_sync(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    void handle_shared_state(
        const Pistache::Rest::Request& req,
        Pistache::Http::ResponseWriter resp);

    std::shared_ptr<BFTQuorumTrustedClock> clock_;
    RestAuthConfig                         auth_;
    ColdVault&                             vault_;
};

} // namespace uml001::rest
