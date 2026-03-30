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
#pragma once

#include <string>
#include <vector>

#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"

namespace uml001::pipeline {

void encode_align_payload(const std::string& peer_id,
                          const std::string& session_id,
                          const std::string& local_anchor,
                          std::string* out);

bool decode_align_payload(const std::string& payload,
                          std::string& peer_id,
                          std::string& session_id,
                          std::string& local_anchor);

void encode_ntp_sync_payload(const std::vector<TimeObservation>& observations,
                             double warp_score,
                             std::string* out);

bool decode_ntp_sync_payload(const std::string& payload,
                             std::vector<TimeObservation>& observations,
                             double& warp_score);

void encode_shared_state_payload(uint64_t monotonic_version,
                                 double warp_score,
                                 uint64_t shared_agreed_time,
                                 int64_t shared_applied_drift,
                                 uint64_t leader_system_time_at_sync,
                                 const std::string& signature_hex,
                                 const std::string& leader_id,
                                 const std::string& key_id,
                                 std::string* out);

bool decode_shared_state_payload(const std::string& payload,
                                 uint64_t& monotonic_version,
                                 double& warp_score,
                                 uint64_t& shared_agreed_time,
                                 int64_t& shared_applied_drift,
                                 uint64_t& leader_system_time_at_sync,
                                 std::string& signature_hex,
                                 std::string& leader_id,
                                 std::string& key_id);

} // namespace uml001::pipeline
