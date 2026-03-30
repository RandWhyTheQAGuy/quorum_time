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
bridge/grpc_server.py

gRPC adapter exposing BridgeTimeService to consumers.

Uses the pure-Python proto definition below (no separate .proto file
needed - grpcio-tools is not a runtime dependency). The service is
intentionally separate from the internal Aegis clock_service.proto so
consumers are not coupled to the BFT daemon's internal API.

Service definition (equivalent proto):

    syntax = "proto3";
    package aegisbridge;

    service BridgeTimeService {
      rpc GetTime (GetTimeRequest) returns (TimeResponse);
      rpc GetTimeAttested (GetTimeRequest) returns (AttestedTimeResponse);
    }

    message GetTimeRequest {
      string format = 1;  // "unix" | "iso8601" | "json" (default "json")
    }

    message TimeResponse {
      int64  unix_seconds    = 1;
      int64  unix_nanos      = 2;
      string iso8601         = 3;
      double uncertainty_ms  = 4;
    }

    message AttestedTimeResponse {
      int64  unix_seconds       = 1;
      int64  unix_nanos         = 2;
      string iso8601            = 3;
      double uncertainty_ms     = 4;
      double drift_ppm          = 5;
      repeated string accepted_sources  = 6;
      repeated string rejected_sources  = 7;
      string quorum_hash        = 8;
    }
"""

from __future__ import annotations

import logging
import sys
from concurrent import futures
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import grpc
from grpc import ServicerContext

from .clock_state import ClockState
from .formats import to_json_envelope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Proto stubs (pure Python - no codegen required at runtime)
# ---------------------------------------------------------------------------

try:
    # Prefer package-local generated stubs.
    from .bridge_pb2 import AttestedTimeResponse, GetTimeRequest, TimeResponse  # type: ignore
    # Generated grpc stubs import bridge_pb2 with an absolute module name.
    # Register an alias so package-local import contexts still work.
    sys.modules.setdefault("bridge_pb2", sys.modules[__package__ + ".bridge_pb2"])
    from .bridge_pb2_grpc import BridgeTimeServiceServicer, add_BridgeTimeServiceServicer_to_server  # type: ignore
    _STUBS_AVAILABLE = True
except ImportError:
    try:
        # Fallback for top-level import contexts.
        from bridge_pb2 import AttestedTimeResponse, GetTimeRequest, TimeResponse  # type: ignore
        from bridge_pb2_grpc import BridgeTimeServiceServicer, add_BridgeTimeServiceServicer_to_server  # type: ignore
        _STUBS_AVAILABLE = True
    except ImportError:
        _STUBS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Reflection-free implementation using grpc.experimental.proto_reflection
# or raw message bytes when stubs are absent.
#
# Production deployments SHOULD generate stubs with:
#   python -m grpc_tools.protoc -I bridge/proto \
#       --python_out=bridge --grpc_python_out=bridge bridge/proto/bridge.proto
# The server_main.py generation step below creates that .proto file.
# ---------------------------------------------------------------------------


class _BridgeServicer:
    """
    gRPC servicer implementation.
    Works whether or not compiled stubs are present by using the generated
    stubs when available and falling back to a descriptor-based approach.
    """

    def __init__(self, state: ClockState) -> None:
        self._state = state

    def GetTime(self, request, context: ServicerContext):
        try:
            at = self._state.get_or_raise()
        except RuntimeError as exc:
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details(str(exc))
            return TimeResponse()

        dt = datetime.fromtimestamp(at.unix_seconds, tz=timezone.utc)
        whole = int(at.unix_seconds)
        nanos = int((at.unix_seconds - whole) * 1_000_000_000)

        resp = TimeResponse()
        resp.unix_seconds = whole
        resp.unix_nanos = nanos
        resp.iso8601 = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        resp.uncertainty_ms = at.uncertainty_ms
        return resp

    def GetTimeAttested(self, request, context: ServicerContext):
        try:
            at = self._state.get_or_raise()
        except RuntimeError as exc:
            context.set_code(grpc.StatusCode.UNAVAILABLE)
            context.set_details(str(exc))
            return AttestedTimeResponse()

        dt = datetime.fromtimestamp(at.unix_seconds, tz=timezone.utc)
        whole = int(at.unix_seconds)
        nanos = int((at.unix_seconds - whole) * 1_000_000_000)

        resp = AttestedTimeResponse()
        resp.unix_seconds = whole
        resp.unix_nanos = nanos
        resp.iso8601 = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        resp.uncertainty_ms = at.uncertainty_ms
        resp.drift_ppm = at.drift_ppm
        resp.accepted_sources.extend(at.accepted_sources)
        resp.rejected_sources.extend(at.rejected_sources)
        resp.quorum_hash = at.quorum_hash_hex
        return resp


def build_grpc_server(
    state: ClockState,
    port: int,
    max_workers: int = 10,
    tls_cert_path: str = "",
    tls_key_path: str = "",
    tls_client_ca_path: str = "",
) -> Optional[grpc.Server]:
    """
    Build and return the gRPC server.  Returns None if stubs are not available
    and logs a clear error so the operator knows to run codegen.
    """
    if not _STUBS_AVAILABLE:
        logger.error(
            "gRPC stubs not found. Run: "
            "python -m grpc_tools.protoc -I bridge/proto "
            "--python_out=bridge --grpc_python_out=bridge bridge/proto/bridge.proto"
        )
        return None

    servicer = _BridgeServicer(state)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    add_BridgeTimeServiceServicer_to_server(servicer, server)
    if tls_cert_path and tls_key_path:
        cert = Path(tls_cert_path).read_bytes()
        key = Path(tls_key_path).read_bytes()
        root = Path(tls_client_ca_path).read_bytes() if tls_client_ca_path else None
        creds = grpc.ssl_server_credentials(
            [(key, cert)],
            root_certificates=root,
            require_client_auth=bool(root),
        )
        bound_port = server.add_secure_port(f"[::]:{port}", creds)
    else:
        bound_port = server.add_insecure_port(f"[::]:{port}")
    setattr(server, "_aegis_bound_port", bound_port)
    return server
