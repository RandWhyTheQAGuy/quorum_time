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
bridge/server_main.py

Entry point for the Aegis bridge process.

Starts:
  1. PollLoop        - background thread driving BFT clock, writes to ClockState
  2. NtpUdpServer    - UDP :1123 (or :123 with CAP_NET_BIND_SERVICE)
  3. REST server     - HTTP :8080  (uvicorn)
  4. WebSocket server- HTTP :8081  (uvicorn, separate app)
  5. gRPC server     - TCP  :9090  (grpcio)

All servers share the single ClockState instance. Shutdown is coordinated
on SIGINT / SIGTERM.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

import uvicorn

from .auth import AuthContext
from .clock_state import ClockState
from .config import BridgeConfig, parse_config
from .grpc_server import build_grpc_server
from .ntp_udp_server import NtpUdpServer
from .poll_loop import PollLoop
from .rest_server import build_app
from .ws_server import build_ws_app

logger = logging.getLogger(__name__)


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )


def _codegen_grpc_stubs(bridge_root: Path) -> bool:
    """
    Generate gRPC Python stubs from bridge.proto if they don't exist yet.
    Runs at startup so the Docker image does not need pre-committed stubs.
    """
    proto_src = bridge_root / "bridge" / "proto" / "bridge.proto"
    stub_out = bridge_root / "bridge"
    pb2 = stub_out / "bridge_pb2.py"
    pb2_grpc = stub_out / "bridge_pb2_grpc.py"

    if pb2.exists() and pb2_grpc.exists():
        logger.debug("gRPC stubs already present, skipping codegen")
        return True

    logger.info("Generating gRPC stubs from %s", proto_src)
    try:
        subprocess.check_call(
            [
                sys.executable, "-m", "grpc_tools.protoc",
                f"-I{proto_src.parent}",
                f"--python_out={stub_out}",
                f"--grpc_python_out={stub_out}",
                str(proto_src),
            ]
        )
        logger.info("gRPC stubs generated at %s", stub_out)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("gRPC codegen failed (grpcio-tools installed?): %s", exc)
        return False


def _validate_grpc_runtime_versions() -> bool:
    def _version_tuple(v: str) -> tuple[int, ...]:
        parts = []
        for token in v.split("."):
            num = ""
            for ch in token:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        return tuple(parts)

    try:
        import grpc
        from google.protobuf import __version__ as protobuf_version
        from bridge import bridge_pb2_grpc  # type: ignore
    except Exception as exc:
        logger.error("gRPC runtime version check failed: %s", exc)
        return False

    generated = getattr(bridge_pb2_grpc, "GRPC_GENERATED_VERSION", "")
    if generated and _version_tuple(grpc.__version__) < _version_tuple(generated):
        logger.error("grpcio %s is older than generated stub requirement %s", grpc.__version__, generated)
        return False

    try:
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        deps = data.get("project", {}).get("dependencies", [])
        minimums = {d.split(">=")[0].strip(): d.split(">=")[1].strip() for d in deps if ">=" in d}
        grpc_min = minimums.get("grpcio")
        protobuf_min = minimums.get("protobuf")
        if grpc_min and _version_tuple(grpc.__version__) < _version_tuple(grpc_min):
            logger.error("grpcio runtime %s is below declared minimum %s", grpc.__version__, grpc_min)
            return False
        if protobuf_min and _version_tuple(protobuf_version) < _version_tuple(protobuf_min):
            logger.error("protobuf runtime %s is below declared minimum %s", protobuf_version, protobuf_min)
            return False
    except Exception as exc:
        logger.error("Failed to evaluate pyproject dependency minimums: %s", exc)
        return False
    return True


def _run_uvicorn(app,
                 host: str,
                 port: int,
                 stop_event: threading.Event,
                 ready_event: threading.Event,
                 failed_event: threading.Event,
                 error_holder: dict,
                 tls_cert: str = "",
                 tls_key: str = "") -> None:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
        ssl_certfile=tls_cert or None,
        ssl_keyfile=tls_key or None,
    )
    server = uvicorn.Server(config)

    def _watcher():
        stop_event.wait()
        server.should_exit = True

    watcher = threading.Thread(target=_watcher, daemon=True)
    watcher.start()
    try:
        def _probe():
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if server.started:
                    ready_event.set()
                    return
                if server.should_exit:
                    break
                time.sleep(0.05)
            failed_event.set()
            error_holder["error"] = f"listener startup timeout on {host}:{port}"

        threading.Thread(target=_probe, daemon=True).start()
        server.run()
        if not ready_event.is_set() and not failed_event.is_set():
            failed_event.set()
            error_holder["error"] = f"listener exited before ready on {host}:{port}"
    except Exception as exc:
        failed_event.set()
        error_holder["error"] = str(exc)


def main(argv: list[str] | None = None) -> int:
    bridge_root = Path(__file__).resolve().parent.parent
    cfg = parse_config(argv)
    cfg.validate()
    _setup_logging(cfg.log_level)

    logger.info("Aegis bridge starting (insecure_dev=%s)", cfg.insecure_dev)

    stubs_ok = _codegen_grpc_stubs(bridge_root)
    if not stubs_ok and not cfg.insecure_dev:
        logger.error("gRPC stub generation failed in production mode")
        return 1
    if stubs_ok and not _validate_grpc_runtime_versions():
        logger.error("gRPC runtime/stub version compatibility check failed")
        return 1

    # ------------------------------------------------------------------ shared state
    state = ClockState(staleness_limit_seconds=cfg.poll_interval_seconds * 10)
    auth = AuthContext(
        bearer_tokens=cfg.bearer_tokens,
        rate_limit_rps=cfg.rate_limit_rps,
        insecure_dev=cfg.insecure_dev,
    )

    # ------------------------------------------------------------------ poll loop
    poll = PollLoop(cfg, state)
    poll.start()

    # Wait up to 5s for first quorum result before opening listeners
    logger.info("Waiting for first quorum result...")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if state.get() is not None:
            break
        time.sleep(0.1)

    if state.get() is None:
        if cfg.bft_fail_closed:
            logger.error("No quorum result after 5s and fail_closed=True - aborting")
            poll.stop()
            return 1
        logger.warning("No quorum result after 5s - opening listeners anyway (insecure_dev)")

    # ------------------------------------------------------------------ NTP UDP
    ntp_port = int(os.environ.get("BRIDGE_NTP_PORT", "1123"))
    ntp = NtpUdpServer(state, port=ntp_port)
    try:
        ntp.start()
    except OSError as exc:
        logger.warning("Could not bind NTP UDP port %d: %s", ntp_port, exc)
        if not cfg.insecure_dev:
            logger.error("NTP listener required in production mode")
            poll.stop()
            return 1

    # ------------------------------------------------------------------ stop event
    stop_event = threading.Event()

    def _on_signal(sig, _frame):
        logger.info("Received signal %s - shutting down", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    # ------------------------------------------------------------------ REST
    rest_app = build_app(state, auth)
    rest_ready = threading.Event()
    rest_failed = threading.Event()
    rest_error: dict = {}
    rest_thread = threading.Thread(
        target=_run_uvicorn,
        args=(rest_app, "0.0.0.0", cfg.rest_port, stop_event, rest_ready, rest_failed, rest_error,
              cfg.mtls_server_cert, cfg.mtls_server_key),
        name="rest-server",
        daemon=True,
    )
    rest_thread.start()
    logger.info("REST server listening on :%d", cfg.rest_port)

    # ------------------------------------------------------------------ WebSocket
    ws_app = build_ws_app(state, auth, cfg.ws_push_interval_seconds)
    ws_ready = threading.Event()
    ws_failed = threading.Event()
    ws_error: dict = {}
    ws_thread = threading.Thread(
        target=_run_uvicorn,
        args=(ws_app, "0.0.0.0", cfg.ws_port, stop_event, ws_ready, ws_failed, ws_error,
              cfg.mtls_server_cert, cfg.mtls_server_key),
        name="ws-server",
        daemon=True,
    )
    ws_thread.start()
    logger.info("WebSocket server listening on :%d", cfg.ws_port)

    # ------------------------------------------------------------------ gRPC
    grpc_server = build_grpc_server(
        state,
        cfg.grpc_port,
        tls_cert_path=cfg.mtls_server_cert,
        tls_key_path=cfg.mtls_server_key,
        tls_client_ca_path=cfg.mtls_ca_cert,
    )
    if not grpc_server:
        if not cfg.insecure_dev:
            logger.error("gRPC listener required in production mode")
            poll.stop()
            ntp.stop()
            return 1
    else:
        grpc_server.start()
        grpc_bound_port = int(getattr(grpc_server, "_aegis_bound_port", 0))
        if grpc_bound_port <= 0 and not cfg.insecure_dev:
            logger.error("gRPC listener failed to bind to :%d", cfg.grpc_port)
            poll.stop()
            ntp.stop()
            grpc_server.stop(grace=0)
            return 1
        logger.info("gRPC server listening on :%d", cfg.grpc_port)

    # Listener readiness barrier for production mode.
    if not cfg.insecure_dev:
        if not rest_ready.wait(timeout=6.0) or rest_failed.is_set():
            logger.error("REST listener failed readiness: %s", rest_error.get("error", "unknown"))
            stop_event.set()
            poll.stop()
            ntp.stop()
            if grpc_server:
                grpc_server.stop(grace=0)
            return 1
        if not ws_ready.wait(timeout=6.0) or ws_failed.is_set():
            logger.error("WS listener failed readiness: %s", ws_error.get("error", "unknown"))
            stop_event.set()
            poll.stop()
            ntp.stop()
            if grpc_server:
                grpc_server.stop(grace=0)
            return 1

    # ------------------------------------------------------------------ wait
    stop_event.wait()

    logger.info("Shutting down...")
    poll.stop()
    ntp.stop()
    if grpc_server:
        grpc_server.stop(grace=2)

    logger.info("Aegis bridge stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
