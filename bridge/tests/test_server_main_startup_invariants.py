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
from __future__ import annotations

from bridge.config import BridgeConfig
from bridge import server_main


class _DummyPollLoop:
    def __init__(self, cfg, state):
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self, timeout=None):
        self.stopped = True


class _DummyNtpServer:
    def __init__(self, state, port):
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def _prod_cfg() -> BridgeConfig:
    return BridgeConfig(
        insecure_dev=False,
        bft_fail_closed=True,
        poll_interval_seconds=0.1,
        rest_port=18080,
        ws_port=18081,
        grpc_port=19090,
        data_dir="/tmp/aegis-bridge-prod-test",
        bearer_tokens="test-token-abc",
        mtls_server_cert="/tmp/server.crt",
        mtls_server_key="/tmp/server.key",
        mtls_ca_cert="/tmp/ca.crt",
    )


def test_production_aborts_on_grpc_codegen_failure(monkeypatch):
    monkeypatch.setattr(server_main, "parse_config", lambda argv=None: _prod_cfg())
    monkeypatch.setattr(server_main, "_setup_logging", lambda level: None)
    monkeypatch.setattr(server_main, "_codegen_grpc_stubs", lambda root: False)
    rc = server_main.main([])
    assert rc == 1


def test_production_aborts_on_ntp_bind_failure(monkeypatch):
    cfg = _prod_cfg()
    cfg.bft_fail_closed = False
    monkeypatch.setattr(server_main, "parse_config", lambda argv=None: cfg)
    monkeypatch.setattr(server_main, "_setup_logging", lambda level: None)
    monkeypatch.setattr(server_main, "_codegen_grpc_stubs", lambda root: True)
    monkeypatch.setattr(server_main, "_validate_grpc_runtime_versions", lambda: True)
    monkeypatch.setattr(server_main, "PollLoop", _DummyPollLoop)

    class _FailingNtp(_DummyNtpServer):
        def start(self):
            raise OSError("bind failed")

    monkeypatch.setattr(server_main, "NtpUdpServer", _FailingNtp)
    monotonic_values = iter([0.0, 6.0, 6.0])
    monkeypatch.setattr(server_main.time, "monotonic", lambda: next(monotonic_values, 6.0))
    monkeypatch.setattr(server_main.time, "sleep", lambda s: None)
    rc = server_main.main([])
    assert rc == 1


def test_production_aborts_when_grpc_listener_missing(monkeypatch):
    cfg = _prod_cfg()
    cfg.bft_fail_closed = False
    monkeypatch.setattr(server_main, "parse_config", lambda argv=None: cfg)
    monkeypatch.setattr(server_main, "_setup_logging", lambda level: None)
    monkeypatch.setattr(server_main, "_codegen_grpc_stubs", lambda root: True)
    monkeypatch.setattr(server_main, "_validate_grpc_runtime_versions", lambda: True)
    monkeypatch.setattr(server_main, "PollLoop", _DummyPollLoop)
    monkeypatch.setattr(server_main, "NtpUdpServer", _DummyNtpServer)
    monkeypatch.setattr(
        server_main,
        "build_grpc_server",
        lambda state, port, tls_cert_path="", tls_key_path="", tls_client_ca_path="": None,
    )

    # Reach listener init path without waiting for quorum.
    monotonic_values = iter([0.0, 6.0, 6.0])
    monkeypatch.setattr(server_main.time, "monotonic", lambda: next(monotonic_values, 6.0))
    monkeypatch.setattr(server_main.time, "sleep", lambda s: None)
    monkeypatch.setattr(server_main, "build_app", lambda state, auth: object())
    monkeypatch.setattr(server_main, "build_ws_app", lambda state, auth, interval: object())
    def _fake_uvicorn(app, host, port, stop_event, ready_event, failed_event, error_holder,
                      tls_cert="", tls_key=""):
        ready_event.set()
    monkeypatch.setattr(server_main, "_run_uvicorn", _fake_uvicorn)

    rc = server_main.main([])
    assert rc == 1


def test_production_aborts_when_rest_listener_not_ready(monkeypatch):
    cfg = _prod_cfg()
    cfg.bft_fail_closed = False
    monkeypatch.setattr(server_main, "parse_config", lambda argv=None: cfg)
    monkeypatch.setattr(server_main, "_setup_logging", lambda level: None)
    monkeypatch.setattr(server_main, "_codegen_grpc_stubs", lambda root: True)
    monkeypatch.setattr(server_main, "_validate_grpc_runtime_versions", lambda: True)
    monkeypatch.setattr(server_main, "PollLoop", _DummyPollLoop)
    monkeypatch.setattr(server_main, "NtpUdpServer", _DummyNtpServer)

    class _DummyGrpcServer:
        _aegis_bound_port = 19090
        def start(self):
            pass
        def stop(self, grace=0):
            pass

    monkeypatch.setattr(
        server_main,
        "build_grpc_server",
        lambda state, port, tls_cert_path="", tls_key_path="", tls_client_ca_path="": _DummyGrpcServer(),
    )

    monotonic_values = iter([0.0, 6.0, 6.0])
    monkeypatch.setattr(server_main.time, "monotonic", lambda: next(monotonic_values, 6.0))
    monkeypatch.setattr(server_main.time, "sleep", lambda s: None)
    monkeypatch.setattr(server_main, "build_app", lambda state, auth: object())
    monkeypatch.setattr(server_main, "build_ws_app", lambda state, auth, interval: object())

    def _fake_uvicorn(app, host, port, stop_event, ready_event, failed_event, error_holder,
                      tls_cert="", tls_key=""):
        if port == cfg.rest_port:
            failed_event.set()
            error_holder["error"] = "bind failed"
            return
        ready_event.set()

    monkeypatch.setattr(server_main, "_run_uvicorn", _fake_uvicorn)
    rc = server_main.main([])
    assert rc == 1
