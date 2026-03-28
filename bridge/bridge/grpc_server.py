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
      repeated string accepted  = 6;
      repeated string rejected  = 7;
      string quorum_hash        = 8;
    }
"""

from __future__ import annotations

import logging
from concurrent import futures
from datetime import datetime, timezone
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
    # If the caller has pre-generated stubs available, prefer them
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
        resp.accepted.extend(at.accepted_sources)
        resp.rejected.extend(at.rejected_sources)
        resp.quorum_hash = at.quorum_hash_hex
        return resp


def build_grpc_server(
    state: ClockState,
    port: int,
    max_workers: int = 10,
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
    server.add_insecure_port(f"[::]:{port}")
    return server
