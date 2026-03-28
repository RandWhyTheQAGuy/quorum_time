"""
bridge/config.py

All configuration for the Aegis bridge, resolved in priority order:
  CLI flags > environment variables > defaults.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field


@dataclass
class BridgeConfig:
    # ------------------------------------------------------------------ paths
    data_dir: str = "/var/lib/aegis/vault"

    # ------------------------------------------------------------------ upstream
    # Quorum daemon connection (localhost inside the sidecar pod)
    upstream_grpc_host: str = "127.0.0.1"
    upstream_grpc_port: int = 50051

    # How often (seconds) the background loop polls the BFT clock
    poll_interval_seconds: float = 1.0

    # ------------------------------------------------------------------ listeners
    rest_port: int = 8080
    ws_port: int = 8081
    grpc_port: int = 9090

    # WebSocket push interval (seconds) – 0 means push on every poll tick
    ws_push_interval_seconds: float = 1.0

    # ------------------------------------------------------------------ auth
    # Comma-separated bearer tokens.  Empty string disables bearer auth.
    bearer_tokens: str = ""

    # Path to a PEM CA cert for mTLS client verification.  Empty disables mTLS.
    mtls_ca_cert: str = ""
    mtls_server_cert: str = ""
    mtls_server_key: str = ""

    # ------------------------------------------------------------------ rate limiting
    # Requests per second per client IP across all HTTP endpoints
    rate_limit_rps: int = 100

    # ------------------------------------------------------------------ ntp
    # NTP server names passed to NtpObservationFetcher
    ntp_servers: list[str] = field(
        default_factory=lambda: [
            "time.cloudflare.com",
            "time.google.com",
            "time.nist.gov",
        ]
    )
    ntp_timeout_ms: int = 1000
    ntp_max_delay_ms: int = 2000

    # ------------------------------------------------------------------ bft
    bft_min_quorum: int = 3
    bft_fail_closed: bool = True

    # ------------------------------------------------------------------ misc
    log_level: str = "INFO"
    insecure_dev: bool = False


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def parse_config(argv: list[str] | None = None) -> BridgeConfig:
    parser = argparse.ArgumentParser(
        prog="aegis-bridge",
        description="Aegis BFT quorum clock consumer bridge",
    )

    parser.add_argument("--data-dir",              default=_env("AEGIS_DATA_DIR", "/var/lib/aegis/vault"))
    parser.add_argument("--upstream-host",         default=_env("AEGIS_UPSTREAM_HOST", "127.0.0.1"))
    parser.add_argument("--upstream-port",         type=int, default=int(_env("AEGIS_UPSTREAM_PORT", "50051")))
    parser.add_argument("--poll-interval",         type=float, default=float(_env("AEGIS_POLL_INTERVAL", "1.0")))
    parser.add_argument("--rest-port",             type=int, default=int(_env("BRIDGE_REST_PORT", "8080")))
    parser.add_argument("--ws-port",               type=int, default=int(_env("BRIDGE_WS_PORT", "8081")))
    parser.add_argument("--grpc-port",             type=int, default=int(_env("BRIDGE_GRPC_PORT", "9090")))
    parser.add_argument("--ws-push-interval",      type=float, default=float(_env("BRIDGE_WS_PUSH_INTERVAL", "1.0")))
    parser.add_argument("--bearer-tokens",         default=_env("BRIDGE_BEARER_TOKENS", ""))
    parser.add_argument("--mtls-ca-cert",          default=_env("BRIDGE_MTLS_CA_CERT", ""))
    parser.add_argument("--mtls-server-cert",      default=_env("BRIDGE_MTLS_SERVER_CERT", ""))
    parser.add_argument("--mtls-server-key",       default=_env("BRIDGE_MTLS_SERVER_KEY", ""))
    parser.add_argument("--rate-limit-rps",        type=int, default=int(_env("BRIDGE_RATE_LIMIT_RPS", "100")))
    parser.add_argument("--ntp-servers",           default=_env("BRIDGE_NTP_SERVERS", "time.cloudflare.com,time.google.com,time.nist.gov"))
    parser.add_argument("--ntp-timeout-ms",        type=int, default=int(_env("BRIDGE_NTP_TIMEOUT_MS", "1000")))
    parser.add_argument("--ntp-max-delay-ms",      type=int, default=int(_env("BRIDGE_NTP_MAX_DELAY_MS", "2000")))
    parser.add_argument("--bft-min-quorum",        type=int, default=int(_env("BRIDGE_BFT_MIN_QUORUM", "3")))
    parser.add_argument("--log-level",             default=_env("BRIDGE_LOG_LEVEL", "INFO"))
    parser.add_argument("--insecure-dev",          action="store_true", default=_env("BRIDGE_INSECURE_DEV", "").lower() in ("1", "true", "yes"))

    args = parser.parse_args(argv)

    return BridgeConfig(
        data_dir=args.data_dir,
        upstream_grpc_host=args.upstream_host,
        upstream_grpc_port=args.upstream_port,
        poll_interval_seconds=args.poll_interval,
        rest_port=args.rest_port,
        ws_port=args.ws_port,
        grpc_port=args.grpc_port,
        ws_push_interval_seconds=args.ws_push_interval,
        bearer_tokens=args.bearer_tokens,
        mtls_ca_cert=args.mtls_ca_cert,
        mtls_server_cert=args.mtls_server_cert,
        mtls_server_key=args.mtls_server_key,
        rate_limit_rps=args.rate_limit_rps,
        ntp_servers=[s.strip() for s in args.ntp_servers.split(",") if s.strip()],
        ntp_timeout_ms=args.ntp_timeout_ms,
        ntp_max_delay_ms=args.ntp_max_delay_ms,
        bft_min_quorum=args.bft_min_quorum,
        bft_fail_closed=not args.insecure_dev,
        log_level=args.log_level,
        insecure_dev=args.insecure_dev,
    )
