/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
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
 *   - BFT Quorum Time: multi-authority, tamper-evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross-domain alignment (AlignTime).
 *
 *   - Transparency Logging: append-only, hash-chained audit records
 *                           for time events, alignment proofs, and
 *                           key-rotation operations.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security-critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open-source project with a focus on
 * clarity, auditability, and long-term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community-driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/pipeline_event_codec.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

namespace uml001::pipeline {

namespace {

void append_chunk(std::string* out, const std::string& chunk)
{
    uint32_t n = static_cast<uint32_t>(chunk.size());
    out->append(reinterpret_cast<const char*>(&n), sizeof(n));
    out->append(chunk);
}

bool read_chunk(const std::string& payload, size_t& off, std::string* chunk)
{
    if (off + sizeof(uint32_t) > payload.size()) return false;
    uint32_t n = 0;
    std::memcpy(&n, payload.data() + off, sizeof(n));
    off += sizeof(n);
    if (off + n > payload.size()) return false;
    chunk->assign(payload.data() + off, n);
    off += n;
    return true;
}

bool parse_u64(const std::string& s, std::uint64_t* out)
{
    try {
        size_t pos = 0;
        const auto v = std::stoull(s, &pos);
        if (pos != s.size()) return false;
        *out = static_cast<std::uint64_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_i64(const std::string& s, std::int64_t* out)
{
    try {
        size_t pos = 0;
        const auto v = std::stoll(s, &pos);
        if (pos != s.size()) return false;
        *out = static_cast<std::int64_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_double(const std::string& s, double* out)
{
    try {
        size_t pos = 0;
        const auto v = std::stod(s, &pos);
        if (pos != s.size()) return false;
        *out = v;
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

void encode_align_payload(const std::string& peer_id,
                          const std::string& session_id,
                          const std::string& local_anchor,
                          std::string* out)
{
    out->clear();
    append_chunk(out, peer_id);
    append_chunk(out, session_id);
    append_chunk(out, local_anchor);
}

bool decode_align_payload(const std::string& payload,
                          std::string& peer_id,
                          std::string& session_id,
                          std::string& local_anchor)
{
    size_t off = 0;
    if (!read_chunk(payload, off, &peer_id)) return false;
    if (!read_chunk(payload, off, &session_id)) return false;
    if (!read_chunk(payload, off, &local_anchor)) return false;
    return off == payload.size();
}

void encode_ntp_sync_payload(const std::vector<TimeObservation>& observations,
                             double warp_score,
                             std::string* out)
{
    std::ostringstream oss;
    oss << "WARP " << warp_score << "\n";
    for (const auto& o : observations) {
        oss << "OBS " << o.server_hostname << '\t' << o.key_id << '\t'
            << o.unix_seconds << '\t' << o.signature_hex << '\t' << o.sequence
            << "\n";
    }
    *out = oss.str();
}

bool decode_ntp_sync_payload(const std::string& payload,
                             std::vector<TimeObservation>& observations,
                             double& warp_score)
{
    observations.clear();
    warp_score = 0.0;
    std::istringstream iss(payload);
    std::string line;
    if (!std::getline(iss, line)) return false;
    if (line.rfind("WARP ", 0) != 0) return false;
    if (!parse_double(line.substr(5), &warp_score)) return false;
    while (std::getline(iss, line)) {
        if (line.rfind("OBS ", 0) != 0) continue;
        std::string rest = line.substr(4);
        std::vector<std::string> parts;
        std::istringstream rs(rest);
        std::string cell;
        while (std::getline(rs, cell, '\t')) {
            parts.push_back(cell);
        }
        if (parts.size() < 5) continue;
        TimeObservation t;
        t.server_hostname = parts[0];
        t.key_id          = parts[1];
        if (!parse_u64(parts[2], &t.unix_seconds)) return false;
        t.signature_hex   = parts[3];
        if (!parse_u64(parts[4], &t.sequence)) return false;
        observations.push_back(t);
    }
    return true;
}

void encode_shared_state_payload(uint64_t monotonic_version,
                                 double warp_score,
                                 uint64_t shared_agreed_time,
                                 int64_t shared_applied_drift,
                                 uint64_t leader_system_time_at_sync,
                                 const std::string& signature_hex,
                                 const std::string& leader_id,
                                 const std::string& key_id,
                                 std::string* out)
{
    std::ostringstream oss;
    oss << monotonic_version << '\n'
        << warp_score << '\n'
        << shared_agreed_time << '\n'
        << shared_applied_drift << '\n'
        << leader_system_time_at_sync << '\n'
        << signature_hex << '\n'
        << leader_id << '\n'
        << key_id;
    *out = oss.str();
}

bool decode_shared_state_payload(const std::string& payload,
                                 uint64_t& monotonic_version,
                                 double& warp_score,
                                 uint64_t& shared_agreed_time,
                                 int64_t& shared_applied_drift,
                                 uint64_t& leader_system_time_at_sync,
                                 std::string& signature_hex,
                                 std::string& leader_id,
                                 std::string& key_id)
{
    std::istringstream iss(payload);
    std::string line;
    if (!std::getline(iss, line)) return false;
    if (!parse_u64(line, &monotonic_version)) return false;
    if (!std::getline(iss, line)) return false;
    if (!parse_double(line, &warp_score)) return false;
    if (!std::getline(iss, line)) return false;
    if (!parse_u64(line, &shared_agreed_time)) return false;
    if (!std::getline(iss, line)) return false;
    if (!parse_i64(line, &shared_applied_drift)) return false;
    if (!std::getline(iss, line)) return false;
    if (!parse_u64(line, &leader_system_time_at_sync)) return false;
    if (!std::getline(iss, signature_hex)) return false;
    if (!std::getline(iss, leader_id)) return false;
    if (!std::getline(iss, key_id)) return false;
    // Reject trailing/smuggled fields to keep a strict contract.
    if (std::getline(iss, line)) return false;
    return true;
}

} // namespace uml001::pipeline
