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
#include "uml001/pipeline_event_codec.h"
#include "uml001/pipeline_event_ids.h"

#include <pistache/http.h>
#include <pistache/router.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace uml001::rest {

namespace {
constexpr const char* kSharedStateFields[] = {
    "monotonic_version",
    "warp_score",
    "shared_agreed_time",
    "shared_applied_drift",
    "leader_system_time_at_sync",
    "signature_hex",
    "leader_id",
    "key_id"
};

template <typename T>
bool extract_typed_field(const json& body,
                         const char* field,
                         T* out,
                         ColdVault& vault,
                         Pistache::Http::ResponseWriter& resp)
{
    try {
        *out = body.at(field).get<T>();
        return true;
    } catch (const std::exception&) {
        vault.log_security_event("rest.time.shared_state.bad_request",
                                 std::string("bad_type=") + field);
        resp.send(Pistache::Http::Code::Bad_Request, "Invalid shared-state field types");
        return false;
    }
}

bool reject_unknown_fields(const json& body,
                           ColdVault& vault,
                           Pistache::Http::ResponseWriter& resp)
{
    if (!body.is_object()) {
        vault.log_security_event("rest.time.shared_state.bad_request", "reason=non_object");
        resp.send(Pistache::Http::Code::Bad_Request, "Invalid shared-state JSON object");
        return true;
    }
    for (const auto& item : body.items()) {
        bool known = false;
        for (const char* f : kSharedStateFields) {
            if (item.key() == f) {
                known = true;
                break;
            }
        }
        if (!known) {
            vault.log_security_event("rest.time.shared_state.bad_request",
                                     std::string("unknown_field=") + item.key());
            resp.send(Pistache::Http::Code::Bad_Request, "Unknown shared-state fields are not allowed");
            return true;
        }
    }
    return false;
}
} // namespace

TimeApiHandler::TimeApiHandler(
    EventOrchestrator&                     orchestrator,
    RestAuthConfig                         auth_config,
    ColdVault&                             vault
)
    : orchestrator_(orchestrator)
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
    SignedState event;
    event.set_event_id(pipeline::REST_AUTH_FAILED);
    event.set_logical_time_ns(0);
    event.set_payload("endpoint=" + endpoint_name + ";reason=" + failure_reason);
    orchestrator_.ingest(event);
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

    SignedState event;
    event.set_event_id(pipeline::REST_TIME_NOW);
    event.set_logical_time_ns(0);
    const auto ctx = orchestrator_.ingest_with_context(event);
    uint64_t t = ctx.grpc_unix_time;
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

    SignedState event;
    event.set_event_id(pipeline::REST_TIME_SYNC);
    event.set_logical_time_ns(0);
    event.set_payload(body.dump());
    orchestrator_.ingest(event);

    resp.send(Pistache::Http::Code::Forbidden,
              "Direct sync mutation disabled; use convergence pipeline");
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

    if (reject_unknown_fields(body, vault_, resp)) {
        return;
    }
    for (const char* f : kSharedStateFields) {
        if (!body.contains(f)) {
            vault_.log_security_event(
                "rest.time.shared_state.bad_request",
                std::string("missing_field=") + f);
            resp.send(Pistache::Http::Code::Bad_Request, "Missing required shared-state fields");
            return;
        }
    }

    uint64_t monotonic_version = 0;
    double warp_score = 0.0;
    uint64_t shared_agreed_time = 0;
    int64_t shared_applied_drift = 0;
    uint64_t leader_system_time_at_sync = 0;
    std::string signature_hex;
    std::string leader_id;
    std::string key_id;

    if (!extract_typed_field(body, "monotonic_version", &monotonic_version, vault_, resp) ||
        !extract_typed_field(body, "warp_score", &warp_score, vault_, resp) ||
        !extract_typed_field(body, "shared_agreed_time", &shared_agreed_time, vault_, resp) ||
        !extract_typed_field(body, "shared_applied_drift", &shared_applied_drift, vault_, resp) ||
        !extract_typed_field(body, "leader_system_time_at_sync", &leader_system_time_at_sync, vault_, resp) ||
        !extract_typed_field(body, "signature_hex", &signature_hex, vault_, resp) ||
        !extract_typed_field(body, "leader_id", &leader_id, vault_, resp) ||
        !extract_typed_field(body, "key_id", &key_id, vault_, resp)) {
        return;
    }

    std::string payload;
    // Keep warp_score in the encoded payload so downstream signature verification
    // can cryptographically bind drift-ceiling policy inputs.
    pipeline::encode_shared_state_payload(
        monotonic_version,
        warp_score,
        shared_agreed_time,
        shared_applied_drift,
        leader_system_time_at_sync,
        signature_hex,
        leader_id,
        key_id,
        &payload);

    SignedState event;
    event.set_event_id(pipeline::REST_TIME_SHARED_STATE);
    event.set_logical_time_ns(0);
    event.set_payload(payload);
    const auto ctx = orchestrator_.ingest_with_context(event);
    if (ctx.rest_shared_state_ok) {
        resp.send(Pistache::Http::Code::Ok, "{\"status\":\"applied\"}");
        return;
    }
    resp.send(Pistache::Http::Code::Forbidden,
              "Shared-state rejected by convergence or signature/version checks");
}

} // namespace uml001::rest
