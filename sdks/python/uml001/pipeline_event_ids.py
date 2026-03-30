# Quorum Time — Open Trusted Time & Distributed Verification Framework
# Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
# SPDX-License-Identifier: Apache-2.0
#
# Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
# system designed for modern distributed environments. It provides a
# cryptographically anchored notion of time that can be aligned,
# audited, and shared across domains without requiring centralized
# trust.
#
# This project also includes the Aegis Semantic Passport components,
# which complement Quorum Time by offering structured, verifiable
# identity and capability attestations for agents and services.
#
# Core capabilities:
#   - BFT Quorum Time: multi-authority, tamper-evident time agreement
#                      with drift bounds, authority attestation, and
#                      cross-domain alignment (AlignTime).
#
#   - Transparency Logging: append-only, hash-chained audit records
#                           for time events, alignment proofs, and
#                           key-rotation operations.
#
#   - Open Integration: designed for interoperability with distributed
#                       systems, security-critical infrastructure,
#                       autonomous agents, and research environments.
#
# Quorum Time is developed as an open-source project with a focus on
# clarity, auditability, and long-term maintainability. Contributions,
# issue reports, and discussions are welcome.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This implementation is intended for open research, practical
# deployment, and community-driven evolution of verifiable time and
# distributed trust standards.
#
"""
Canonical pipeline event identifiers.

Mirrors include/uml001/pipeline_event_ids.h (single source of truth in C++).
"""

# gRPC
GRPC_GET_TIME = "uml001.grpc.GetTime"
GRPC_GET_STATUS = "uml001.grpc.GetStatus"
GRPC_ALIGN_TIME = "uml001.grpc.AlignTime"

REST_PREFIX = "uml001.rest."
REST_TIME_NOW = "uml001.rest.time.now"
REST_TIME_SYNC = "uml001.rest.time.sync"
REST_TIME_SHARED_STATE = "uml001.rest.time.shared_state"
REST_AUTH_FAILED = "uml001.rest.auth_failed"

WORKER_NTP_SYNC = "uml001.worker.ntp_sync"
INTERNAL_SHARED_STATE_APPLY = "uml001.internal.shared_state.apply"

CONTROL_SET_MODE = "uml001.control.set_mode"
CONTROL_HITL_APPROVE = "uml001.control.hitl.approve"
CONTROL_HITL_REJECT = "uml001.control.hitl.reject"
CONTROL_RECOVERY_BEGIN = "uml001.control.recovery.begin"
CONTROL_RECOVERY_EPOCH_VERIFIED = "uml001.control.recovery.epoch_verified"
CONTROL_RECOVERY_REJOIN = "uml001.control.recovery.rejoin"

ALL_KNOWN = (
    GRPC_GET_TIME,
    GRPC_GET_STATUS,
    GRPC_ALIGN_TIME,
    REST_TIME_NOW,
    REST_TIME_SYNC,
    REST_TIME_SHARED_STATE,
    REST_AUTH_FAILED,
    WORKER_NTP_SYNC,
    INTERNAL_SHARED_STATE_APPLY,
    CONTROL_SET_MODE,
    CONTROL_HITL_APPROVE,
    CONTROL_HITL_REJECT,
    CONTROL_RECOVERY_BEGIN,
    CONTROL_RECOVERY_EPOCH_VERIFIED,
    CONTROL_RECOVERY_REJOIN,
)
