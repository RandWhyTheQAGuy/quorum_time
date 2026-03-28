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


def _codegen_grpc_stubs(bridge_root: Path) -> None:
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
        return

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
    except subprocess.CalledProcessError as exc:
        logger.error("gRPC codegen failed (grpcio-tools installed?): %s", exc)


def _run_uvicorn(app, host: str, port: int, stop_event: threading.Event) -> None:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)

    def _watcher():
        stop_event.wait()
        server.should_exit = True

    watcher = threading.Thread(target=_watcher, daemon=True)
    watcher.start()
    server.run()


def main(argv: list[str] | None = None) -> int:
    bridge_root = Path(__file__).resolve().parent.parent
    cfg = parse_config(argv)
    _setup_logging(cfg.log_level)

    logger.info("Aegis bridge starting (insecure_dev=%s)", cfg.insecure_dev)

    _codegen_grpc_stubs(bridge_root)

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

    # ------------------------------------------------------------------ stop event
    stop_event = threading.Event()

    def _on_signal(sig, _frame):
        logger.info("Received signal %s - shutting down", sig)
        stop_event.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    # ------------------------------------------------------------------ REST
    rest_app = build_app(state, auth)
    rest_thread = threading.Thread(
        target=_run_uvicorn,
        args=(rest_app, "0.0.0.0", cfg.rest_port, stop_event),
        name="rest-server",
        daemon=True,
    )
    rest_thread.start()
    logger.info("REST server listening on :%d", cfg.rest_port)

    # ------------------------------------------------------------------ WebSocket
    ws_app = build_ws_app(state, auth, cfg.ws_push_interval_seconds)
    ws_thread = threading.Thread(
        target=_run_uvicorn,
        args=(ws_app, "0.0.0.0", cfg.ws_port, stop_event),
        name="ws-server",
        daemon=True,
    )
    ws_thread.start()
    logger.info("WebSocket server listening on :%d", cfg.ws_port)

    # ------------------------------------------------------------------ gRPC
    grpc_server = build_grpc_server(state, cfg.grpc_port)
    if grpc_server:
        grpc_server.start()
        logger.info("gRPC server listening on :%d", cfg.grpc_port)

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
