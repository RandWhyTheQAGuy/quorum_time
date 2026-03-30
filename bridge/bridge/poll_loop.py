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
bridge/poll_loop.py

Background thread that owns the uml001 BFT clock, drives the NTP fetch
loop, and writes fresh AttestedTime snapshots to ClockState on every tick.

Nothing else in the bridge touches the C++ objects directly.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from .clock_state import ClockState
from .config import BridgeConfig
from .formats import AttestedTime

logger = logging.getLogger(__name__)


def _build_quorum_hash(accepted: list[str], unix_seconds: float) -> str:
    """
    Deterministic hex digest over the quorum membership + agreed time.
    Mirrors the logic the C++ vault uses so downstream consumers can
    cross-check the value.
    """
    payload = ",".join(sorted(accepted)) + f"|{int(unix_seconds)}"
    return hashlib.sha256(payload.encode()).hexdigest()


class PollLoop:
    """
    Owns the C++ uml001 objects and drives periodic BFT sync.
    Call start() to launch the background thread.
    Call stop() to shut it down cleanly.
    """

    def __init__(self, cfg: BridgeConfig, state: ClockState) -> None:
        self._cfg = cfg
        self._state = state
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Lazy import so the module can be tested without the .so present
        self._clock = None
        self._fetcher = None
        self._vault = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _init_uml001(self) -> None:
        """Initialise all C++ objects.  Called inside the thread."""
        import _uml001 as u

        data_dir = Path(self._cfg.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)

        strong_clock = u.OsStrongClock()
        hash_provider = u.SimpleHashProvider()

        vault_cfg = u.ColdVaultConfig()
        vault_cfg.base_directory = str(data_dir)

        backend = u.SimpleFileVaultBackend(str(data_dir / "vault.log"))
        vault = u.ColdVault(vault_cfg, backend, strong_clock, hash_provider)
        self._vault = vault

        bft_cfg = u.BftClockConfig()
        bft_cfg.min_quorum = self._cfg.bft_min_quorum
        bft_cfg.fail_closed = self._cfg.bft_fail_closed

        authorities = set(self._cfg.ntp_servers)
        self._clock = u.BFTQuorumTrustedClock(bft_cfg, authorities, vault)

        servers = [
            u.NtpServerEntry() for _ in self._cfg.ntp_servers
        ]
        for entry, hostname in zip(servers, self._cfg.ntp_servers):
            entry.hostname = hostname
            entry.timeout_ms = self._cfg.ntp_timeout_ms
            entry.max_delay_ms = self._cfg.ntp_max_delay_ms

        hmac_key = os.environ.get("UML001_HMAC_KEY", "")
        self._fetcher = u.NtpObservationFetcher(
            hmac_key,
            "bridge-key-0",
            servers,
            self._cfg.bft_min_quorum,
            self._cfg.ntp_timeout_ms,
            self._cfg.ntp_max_delay_ms,
        )

        logger.info(
            "uml001 initialised: quorum=%d fail_closed=%s servers=%s",
            self._cfg.bft_min_quorum,
            self._cfg.bft_fail_closed,
            self._cfg.ntp_servers,
        )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("PollLoop is already running")
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="aegis-poll-loop",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning(
                    "Poll loop thread did not exit within %.1fs", timeout
                )

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        try:
            self._init_uml001()
        except Exception:
            logger.exception("Fatal: failed to initialise uml001 objects")
            return

        logger.info("Poll loop started (interval=%.2fs)", self._cfg.poll_interval_seconds)

        while not self._stop_event.is_set():
            tick_start = time.monotonic()
            try:
                self._tick()
            except Exception:
                self._state.record_error()
                logger.exception("Poll tick raised an unexpected exception")

            elapsed = time.monotonic() - tick_start
            sleep_for = max(0.0, self._cfg.poll_interval_seconds - elapsed)
            self._stop_event.wait(timeout=sleep_for)

        logger.info("Poll loop stopped")

    def _tick(self) -> None:
        observations = self._fetcher.fetch()
        result = self._clock.update_and_sync(observations, 0.0)

        if result is None:
            # The C extension signals quorum failure or a transient network
            # error by returning None rather than raising.  Record the miss
            # so health checks can surface it, then wait for the next tick.
            logger.warning(
                "update_and_sync returned None — quorum not met or all NTP "
                "servers unreachable; will retry in %.2fs",
                self._cfg.poll_interval_seconds,
            )
            self._state.record_error()
            return

        accepted = list(result.accepted_sources) if result.accepted_sources else []
        rejected = list(result.rejected_sources) if result.rejected_sources else []

        # Read clock state only after a confirmed successful sync so we never
        # publish stale or uninitialised values from the C++ layer.
        unix_seconds = self._clock.now_unix()
        uncertainty_ms = self._clock.get_current_uncertainty() * 1000.0
        drift_ppm = self._clock.get_current_drift() * 1_000_000.0

        quorum_hash = _build_quorum_hash(accepted, unix_seconds)

        at = AttestedTime(
            unix_seconds=unix_seconds,
            uncertainty_ms=uncertainty_ms,
            drift_ppm=drift_ppm,
            accepted_sources=accepted,
            rejected_sources=rejected,
            quorum_hash_hex=quorum_hash,
            local_mono_ns=time.monotonic_ns(),
        )

        self._state.update(at)

        logger.debug(
            "Tick OK — unix=%.3f uncertainty_ms=%.3f drift_ppm=%.3f "
            "accepted=%s rejected=%s",
            unix_seconds,
            uncertainty_ms,
            drift_ppm,
            accepted,
            rejected,
        )

        if self._vault:
            try:
                self._vault.log_sync_event(
                    int(unix_seconds),
                    drift_ppm / 1_000_000.0,
                    len(accepted),
                    len(rejected),
                )
            except Exception:
                logger.debug("vault.log_sync_event unavailable in this build")