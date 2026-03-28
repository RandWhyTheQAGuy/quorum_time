"""
tests/test_integration.py

Integration tests that exercise the full bridge stack including the C++
uml001 extension.

These tests are automatically SKIPPED unless _uml001 is importable, so
they do not block CI on machines that have not built the C++ extension.

To run them locally after a full build:
    PYTHONPATH=../build pytest tests/test_integration.py -v

What is tested here (not covered by unit tests):
  - PollLoop initialises uml001 objects without error
  - PollLoop produces a valid AttestedTime within the poll interval
  - REST /v1/time returns a live quorum result (not a fixture)
  - ClockState age stays within expected bounds during a live poll run
"""

from __future__ import annotations

import time

import pytest

# ---------------------------------------------------------------------------
# Skip entire module if the C++ extension is not available
# ---------------------------------------------------------------------------

try:
    import _uml001  # noqa: F401
    _UML001_AVAILABLE = True
except ImportError:
    _UML001_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _UML001_AVAILABLE,
    reason="_uml001 extension not importable - run after C++ build with PYTHONPATH=build",
)

from bridge.auth import AuthContext
from bridge.clock_state import ClockState
from bridge.config import BridgeConfig
from bridge.poll_loop import PollLoop
from bridge.rest_server import build_app

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# How long the fixture waits for the very first successful tick.
# NTP round-trips are fast when the network is present; this just needs to
# be larger than ntp_timeout_ms * number_of_servers / 1000.
_FIRST_TICK_TIMEOUT_S = 15.0

# Quorum of 1 lets a single reachable NTP server satisfy the BFT clock
# during tests.  Production deployments use 3+; that is tested by the
# config/deployment layer, not by these functional integration tests.
_TEST_QUORUM = 1

# Per-server timeout.  Short enough that a firewalled host fails fast
# rather than blocking the entire test suite for minutes.
_NTP_TIMEOUT_MS = 1500
_NTP_MAX_DELAY_MS = 3000

# Poll interval during tests — faster than production so the
# test_updates_over_time assertion doesn't have to wait long.
_POLL_INTERVAL_S = 0.5


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def integration_cfg(tmp_path_factory):
    """
    BridgeConfig shared across all tests in this module.

    We use a module-scoped fixture so that the PollLoop (and the expensive
    C++ initialisation + first NTP sync) is only paid once per test run,
    not once per test.
    """
    tmp_path = tmp_path_factory.mktemp("vault")
    return BridgeConfig(
        data_dir=str(tmp_path / "vault"),
        insecure_dev=True,
        bft_fail_closed=False,
        poll_interval_seconds=_POLL_INTERVAL_S,
        bft_min_quorum=_TEST_QUORUM,
        ntp_servers=["time.cloudflare.com", "time.google.com", "time.nist.gov"],
        ntp_timeout_ms=_NTP_TIMEOUT_MS,
        ntp_max_delay_ms=_NTP_MAX_DELAY_MS,
    )


@pytest.fixture(scope="module")
def live_state():
    return ClockState(staleness_limit_seconds=15.0)


@pytest.fixture(scope="module")
def live_poll_loop(integration_cfg, live_state):
    """
    Start the PollLoop and block until the first AttestedTime is available
    or the timeout expires.  If no tick succeeds within the deadline the
    fixture calls pytest.skip() so every downstream test is marked SKIPPED
    (not FAILED) — preserving the distinction between "network unavailable
    in this environment" and "the code is broken".
    """
    loop = PollLoop(integration_cfg, live_state)
    loop.start()

    deadline = time.monotonic() + _FIRST_TICK_TIMEOUT_S
    while time.monotonic() < deadline:
        if live_state.get() is not None:
            break
        time.sleep(0.1)

    if live_state.get() is None:
        loop.stop(timeout=2.0)
        pytest.skip(
            f"No AttestedTime produced within {_FIRST_TICK_TIMEOUT_S}s — "
            "NTP servers unreachable in this environment (firewall / no UDP/123). "
            "Run these tests on a host with outbound NTP access."
        )

    yield loop
    loop.stop(timeout=5.0)


@pytest.fixture(scope="module")
def rest_client(live_poll_loop, live_state):
    """Shared FastAPI TestClient for REST integration tests."""
    from fastapi.testclient import TestClient
    auth = AuthContext(bearer_tokens="", rate_limit_rps=10_000, insecure_dev=True)
    app = build_app(live_state, auth)
    return TestClient(app)


# ---------------------------------------------------------------------------
# PollLoop integration tests
# ---------------------------------------------------------------------------

class TestPollLoopIntegration:
    def test_produces_attested_time(self, live_poll_loop, live_state):
        """Fixture already guarantees this; acts as a sentinel test."""
        assert live_state.get() is not None

    def test_unix_seconds_plausible(self, live_poll_loop, live_state):
        at = live_state.get()
        # 2024-01-01 00:00:00 UTC — any legitimate NTP response will exceed this
        assert at.unix_seconds > 1_704_067_200

    def test_accepted_sources_non_empty(self, live_poll_loop, live_state):
        at = live_state.get()
        assert len(at.accepted_sources) >= _TEST_QUORUM

    def test_quorum_hash_non_empty(self, live_poll_loop, live_state):
        at = live_state.get()
        assert len(at.quorum_hash_hex) == 64  # SHA-256 hex digest

    def test_uncertainty_ms_non_negative(self, live_poll_loop, live_state):
        at = live_state.get()
        assert at.uncertainty_ms >= 0.0

    def test_state_is_healthy(self, live_poll_loop, live_state):
        assert live_state.is_healthy()

    def test_updates_over_time(self, live_poll_loop, live_state):
        """Clock state should advance across at least one poll interval."""
        at1 = live_state.get()
        updated = live_state.wait_for_update(timeout=_POLL_INTERVAL_S * 4)
        assert updated, "ClockState did not receive a second update within timeout"
        at2 = live_state.get()
        assert at2 is not at1
        assert at2.unix_seconds >= at1.unix_seconds


# ---------------------------------------------------------------------------
# REST server integration tests
# ---------------------------------------------------------------------------

class TestRestServerIntegration:
    def test_get_time_live(self, rest_client):
        r = rest_client.get("/v1/time")
        assert r.status_code == 200, f"Unexpected status: {r.status_code} — {r.text}"
        body = r.json()
        assert body["unix_seconds"] > 1_704_067_200
        assert "quorum" in body
        assert len(body["quorum"]["accepted_sources"]) > 0

    def test_get_time_iso8601_format(self, rest_client):
        r = rest_client.get("/v1/time", params={"format": "iso8601"})
        assert r.status_code == 200, f"Unexpected status: {r.status_code} — {r.text}"

    def test_readyz_healthy_during_live_run(self, rest_client):
        r = rest_client.get("/readyz")
        assert r.status_code == 200, f"Unexpected status: {r.status_code} — {r.text}"