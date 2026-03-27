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
#include "uml001/rest_handlers.h"

#include <pistache/http.h>
#include <pistache/router.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace uml001::rest {

TimeApiHandler::TimeApiHandler(
    std::shared_ptr<BFTQuorumTrustedClock> clock,
    RestAuthConfig                         auth_config,
    ColdVault&                             vault
)
    : clock_(std::move(clock))
    , auth_(std::move(auth_config))
    , vault_(vault)
{}

void TimeApiHandler::setup_routes(Pistache::Rest::Router& router) {
    using namespace Pistache::Rest;

    Routes::Get(router, "/time/now",
        Routes::bind(&TimeApiHandler::handle_now, this));

    Routes::Post(router, "/time/sync",
        Routes::bind(&TimeApiHandler::handle_sync, this));

    Routes::Post(router, "/time/shared-state",
        Routes::bind(&TimeApiHandler::handle_shared_state, this));
}

bool TimeApiHandler::check_auth(
    const Pistache::Rest::Request& req,
    const std::string&             endpoint_name,
    std::string&                   failure_reason)
{
    switch (auth_.mode) {
    case RestAuthMode::NONE:
        return true;

    case RestAuthMode::API_KEY: {
        auto hdr = req.headers().tryGetRaw("X-API-Key");
        if (!hdr) {
            failure_reason = "missing X-API-Key";
            break;
        }
        if (hdr->value() != auth_.api_key) {
            failure_reason = "invalid API key";
            break;
        }
        return true;
    }

    case RestAuthMode::MTLS: {
        auto hdr = req.headers().tryGetRaw("X-Client-Identity");
        if (!hdr) {
            failure_reason = "missing X-Client-Identity";
            break;
        }
        const std::string id = hdr->value();
        for (const auto& allowed : auth_.allowed_identities) {
            if (id == allowed) return true;
        }
        failure_reason = "unauthorized identity: " + id;
        break;
    }
    }

    vault_.log_security_event(
        "rest.auth.failed",
        "endpoint=" + endpoint_name + " reason=" + failure_reason
    );
    return false;
}

void TimeApiHandler::handle_now(
    const Pistache::Rest::Request& req,
    Pistache::Http::ResponseWriter resp)
{
    std::string reason;
    if (!check_auth(req, "time.now", reason)) {
        resp.send(Pistache::Http::Code::Unauthorized, "Unauthorized");
        return;
    }

    uint64_t t = clock_->now_unix();
    json j = { {"unix_time", t} };

    vault_.log_security_event("rest.time.now", "unix_time=" + std::to_string(t));
    resp.send(Pistache::Http::Code::Ok, j.dump());
}

void TimeApiHandler::handle_sync(
    const Pistache::Rest::Request& req,
    Pistache::Http::ResponseWriter resp)
{
    std::string reason;
    if (!check_auth(req, "time.sync", reason)) {
        resp.send(Pistache::Http::Code::Unauthorized, "Unauthorized");
        return;
    }

    json body;
    try { body = json::parse(req.body()); }
    catch (...) {
        vault_.log_security_event("rest.time.sync.bad_json", "");
        resp.send(Pistache::Http::Code::Bad_Request, "Invalid JSON");
        return;
    }

    double warp = body.value("warp_score", 0.0);

    std::vector<TimeObservation> obs;
    for (auto& o : body["observations"]) {
        TimeObservation t;
        t.server_hostname = o["server_hostname"];
        t.key_id          = o["key_id"];
        t.unix_seconds    = o["unix_seconds"];
        t.signature_hex   = o["signature_hex"];
        t.sequence        = o["sequence"];
        obs.push_back(t);
    }

    auto result = clock_->update_and_sync(obs, warp);
    if (!result) {
        vault_.log_security_event(
            "rest.time.sync.failed",
            "warp_score=" + std::to_string(warp)
        );
        resp.send(Pistache::Http::Code::Conflict,
                  "Sync failed (quorum or drift ceiling)");
        return;
    }

    // JSON field name stays "applied_drift" to match BFT_SYNC_RESULT_SCHEMA,
    // but the value comes from BftSyncResult::drift_step.
    json j = {
        {"agreed_time",      result->agreed_time},
        {"applied_drift",    result->drift_step},
        {"accepted_sources", result->accepted_sources},
        {"outliers_ejected", result->outliers_ejected},
        {"rejected_sources", result->rejected_sources}
    };

    vault_.log_security_event(
        "rest.time.sync.ok",
        "agreed_time=" + std::to_string(result->agreed_time)
    );

    resp.send(Pistache::Http::Code::Ok, j.dump());
}

void TimeApiHandler::handle_shared_state(
    const Pistache::Rest::Request& req,
    Pistache::Http::ResponseWriter resp)
{
    std::string reason;
    if (!check_auth(req, "time.shared_state", reason)) {
        resp.send(Pistache::Http::Code::Unauthorized, "Unauthorized");
        return;
    }

    json body;
    try { body = json::parse(req.body()); }
    catch (...) {
        vault_.log_security_event("rest.time.shared_state.bad_json", "");
        resp.send(Pistache::Http::Code::Bad_Request, "Invalid JSON");
        return;
    }

    // New fields: monotonic_version (uint64) + warp_score (double, optional)
    uint64_t monotonic_version = body.value("monotonic_version", uint64_t{0});
    double   warp              = body.value("warp_score", 0.0);

    bool ok = clock_->apply_shared_state(
        body["shared_agreed_time"],
        body["shared_applied_drift"],
        body["leader_system_time_at_sync"],
        body["signature_hex"],
        body["leader_id"],
        body["key_id"],
        monotonic_version,
        warp
    );

    if (!ok) {
        vault_.log_security_event(
            "rest.time.shared_state.rejected",
            "leader=" + body["leader_id"].get<std::string>()
        );
        resp.send(Pistache::Http::Code::Conflict,
                  "Shared state rejected");
        return;
    }

    vault_.log_security_event(
        "rest.time.shared_state.adopted",
        "leader=" + body["leader_id"].get<std::string>()
    );

    resp.send(Pistache::Http::Code::Ok, "Shared state adopted");
}

} // namespace uml001::rest
