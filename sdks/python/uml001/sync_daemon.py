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
uml001.sync_daemon
==================
Python equivalent of the background sync loop and Redis coordination
from main_ntp.cpp.

Classes
-------
SharedClockState
    Shared BFT clock state (agreed_time, applied_drift, last_updated_unix).
ISharedClockStore (ABC)
    Interface for a shared state backend (Redis, in-memory, etc.).
InMemorySharedStore
    Thread-safe in-memory implementation (matches the C++ ``RedisSharedStore``
    mock from main_ntp.cpp).
RedisSharedStore
    Production Redis-backed implementation using the ``redis`` package
    (optional dependency; ``ImportError`` raised if not installed).
BFTSyncDaemon
    Background sync loop that coordinates via a shared store, mirrors the
    C++ ``background_sync_loop`` function.

Usage
-----
::

    from uml001 import BFTSyncDaemon, BFTClockConfig, BFTQuorumTrustedClock
    from uml001 import ColdVault, VaultConfig, NtpObservationFetcher
    from uml001 import register_hmac_authority, generate_random_bytes_hex

    hmac_key = generate_random_bytes_hex(32)
    vault = ColdVault()
    fetcher = NtpObservationFetcher(hmac_key)
    clock = BFTQuorumTrustedClock(BFTClockConfig(), {...}, vault)
    store = InMemorySharedStore()

    daemon = BFTSyncDaemon(clock, fetcher, vault, store, sync_interval_s=60)
    daemon.start()
    # ... application runs ...
    daemon.stop()
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Callable

from .bft_clock import BFTQuorumTrustedClock, BftSyncResult
from .ntp_fetcher import NtpObservationFetcher
from .vault import ColdVault

logger = logging.getLogger("uml001.sync_daemon")


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

@dataclass
class SharedClockState:
    """Mirrors the C++ ``SharedClockState`` struct from main_ntp.cpp."""
    agreed_time: int
    applied_drift: int
    last_updated_unix: int


# ---------------------------------------------------------------------------
# Abstract shared store
# ---------------------------------------------------------------------------

class ISharedClockStore(ABC):
    """Abstract shared state backend.

    Mirrors the C++ ``RedisSharedStore`` interface from main_ntp.cpp.

    Both ``read_state`` and ``watch_and_commit`` are expected to be
    thread-safe.
    """

    @abstractmethod
    def read_state(self) -> Optional[SharedClockState]:
        """Return the current shared state, or ``None`` if uninitialised."""

    @abstractmethod
    def watch_and_commit(self, new_state: SharedClockState) -> bool:
        """Attempt an atomic compare-and-swap update.

        Returns ``True`` if the commit succeeded.  Returns ``False`` if
        another node committed a newer state in the meantime
        (mirrors the C++ ``WATCH/MULTI/EXEC`` optimistic-lock protocol).
        """


# ---------------------------------------------------------------------------
# In-memory implementation (mirrors the C++ mock)
# ---------------------------------------------------------------------------

class InMemorySharedStore(ISharedClockStore):
    """Thread-safe in-memory shared store.

    Direct Python equivalent of the ``RedisSharedStore`` mock in
    main_ntp.cpp.  Suitable for single-process use and unit tests.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Optional[SharedClockState] = None

    def read_state(self) -> Optional[SharedClockState]:
        with self._lock:
            return self._state

    def watch_and_commit(self, new_state: SharedClockState) -> bool:
        with self._lock:
            self._state = new_state
            return True


# ---------------------------------------------------------------------------
# Redis-backed implementation (optional)
# ---------------------------------------------------------------------------

class RedisSharedStore(ISharedClockStore):
    """Redis-backed shared state store.

    Implements the WATCH/MULTI/EXEC optimistic-lock pattern described in
    the C++ ``RedisSharedStore`` mock and in ``redis_clock_store.h``.

    Requires the ``redis`` package::

        pip install redis

    Parameters
    ----------
    host, port, password, db:
        Standard Redis connection parameters.
    key_prefix:
        Namespace prefix for all Redis keys (default: ``"uml001:clock:"``)
    max_retries:
        Number of WATCH/MULTI/EXEC retry attempts before returning False.
    timeout_ms:
        Socket timeout in milliseconds.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
        key_prefix: str = "uml001:clock:",
        max_retries: int = 5,
        timeout_ms: int = 500,
    ) -> None:
        try:
            import redis as _redis
        except ImportError as exc:
            raise ImportError(
                "RedisSharedStore requires the 'redis' package: pip install redis"
            ) from exc

        self._redis = _redis.Redis(
            host=host,
            port=port,
            password=password,
            db=db,
            socket_timeout=timeout_ms / 1000.0,
            decode_responses=True,
        )
        self._prefix = key_prefix
        self._max_retries = max_retries

    def read_state(self) -> Optional[SharedClockState]:
        try:
            agreed = self._redis.get(self._prefix + "agreed_time")
            if agreed is None:
                return None
            return SharedClockState(
                agreed_time=int(agreed),
                applied_drift=int(self._redis.get(self._prefix + "applied_drift") or 0),
                last_updated_unix=int(self._redis.get(self._prefix + "updated_at") or 0),
            )
        except Exception as exc:
            logger.warning("RedisSharedStore.read_state failed: %s", exc)
            return None

    def watch_and_commit(self, new_state: SharedClockState) -> bool:
        watch_key = self._prefix + "agreed_time"
        for _ in range(self._max_retries):
            try:
                pipe = self._redis.pipeline(True)
                pipe.watch(watch_key)
                pipe.multi()
                pipe.set(self._prefix + "agreed_time",   str(new_state.agreed_time))
                pipe.set(self._prefix + "applied_drift", str(new_state.applied_drift))
                pipe.set(self._prefix + "updated_at",    str(new_state.last_updated_unix))
                pipe.execute()
                return True
            except Exception:
                # WATCH conflict or connection error – retry
                continue
        return False


# ---------------------------------------------------------------------------
# Background sync daemon
# ---------------------------------------------------------------------------

class BFTSyncDaemon:
    """Background BFT clock synchronisation daemon.

    Mirrors the C++ ``background_sync_loop`` function from main_ntp.cpp,
    promoted to a reusable class.

    Behaviour
    ---------
    1. Every *tick_interval_ms* ms, check the shared store for staleness.
       Log a degradation warning if ``|now - last_updated| > degradation_window_s``.
    2. Every *sync_interval_s* seconds, attempt a sync:
       a. If another node updated the store within ``sync_interval_s / 2``
          seconds, adopt its state via ``apply_shared_state`` and skip local
          NTP fetch.
       b. Otherwise, fetch NTP observations, run BFT consensus, and commit
          the result to the shared store.
    3. After a successful commit, persist NTP sequences to the vault.

    Parameters
    ----------
    clock:
        ``BFTQuorumTrustedClock`` instance.
    fetcher:
        ``NtpObservationFetcher`` instance.
    vault:
        ``ColdVault`` instance.
    shared_store:
        Shared state backend.
    sync_interval_s:
        Target interval between active NTP fetches (seconds).
    degradation_window_s:
        If shared state has not been updated within this window, emit a
        degradation warning.
    tick_interval_ms:
        Internal polling granularity (default 500 ms, matching C++).
    on_sync:
        Optional callback invoked with ``BftSyncResult`` after each
        successful BFT consensus round.
    on_degradation:
        Optional callback invoked when the degradation window is exceeded.
    """

    def __init__(
        self,
        clock: BFTQuorumTrustedClock,
        fetcher: NtpObservationFetcher,
        vault: ColdVault,
        shared_store: ISharedClockStore,
        sync_interval_s: int = 60,
        degradation_window_s: int = 120,
        tick_interval_ms: int = 500,
        on_sync: Optional[Callable[[BftSyncResult], None]] = None,
        on_degradation: Optional[Callable[[int], None]] = None,
    ) -> None:
        self._clock = clock
        self._fetcher = fetcher
        self._vault = vault
        self._store = shared_store
        self._sync_interval_s = sync_interval_s
        self._degradation_window_s = degradation_window_s
        self._tick_interval_s = tick_interval_ms / 1000.0
        self._on_sync = on_sync
        self._on_degradation = on_degradation

        self._shutdown = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background sync thread."""
        if self._thread and self._thread.is_alive():
            return
        self._shutdown.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="uml001-bft-sync",
            daemon=True,
        )
        self._thread.start()
        logger.info("BFTSyncDaemon started (interval=%ss)", self._sync_interval_s)

    def stop(self, timeout_s: float = 5.0) -> None:
        """Signal the sync thread to stop and wait for it to exit."""
        self._shutdown.set()
        if self._thread:
            self._thread.join(timeout=timeout_s)
        logger.info("BFTSyncDaemon stopped")

    def is_running(self) -> bool:
        """Return True if the background thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        ticks_per_interval = max(
            1, int(self._sync_interval_s / self._tick_interval_s)
        )
        # Trigger immediately on first iteration (mirrors C++ tick_count = ticks_total)
        tick_count = ticks_per_interval

        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=self._tick_interval_s)
            if self._shutdown.is_set():
                break

            now = int(time.time())

            # --- Degradation check (every tick) ---
            shared = self._store.read_state()
            if shared is not None:
                age = now - shared.last_updated_unix
                if age > self._degradation_window_s:
                    logger.warning(
                        "[DEGRADATION WARN] Shared clock state is stale! "
                        "Age=%ds exceeds degradation_window=%ds",
                        age, self._degradation_window_s,
                    )
                    if self._on_degradation:
                        try:
                            self._on_degradation(age)
                        except Exception:
                            pass

            tick_count += 1
            if tick_count < ticks_per_interval:
                continue
            tick_count = 0

            try:
                self._sync_once(now, shared)
            except Exception as exc:
                logger.error("[CLOCK SYNC ERROR] %s", exc)

    def _sync_once(
        self,
        now: int,
        shared: Optional[SharedClockState],
    ) -> None:
        """Perform one sync iteration."""
        # If a peer recently committed, adopt its state instead of fetching NTP
        if (
            shared is not None
            and (now - shared.last_updated_unix) < self._sync_interval_s // 2
        ):
            logger.debug(
                "[SYNC] Peer updated %ds ago; adopting shared state",
                now - shared.last_updated_unix,
            )
            self._clock.apply_shared_state(
                shared.agreed_time,
                shared.applied_drift,
                leader_system_time_at_sync=shared.last_updated_unix,
            )
            return

        # We are the active node: fetch NTP and run BFT
        observations = self._fetcher.fetch()
        if not observations:
            logger.debug("[SYNC] No NTP observations returned; skipping round")
            return

        result = self._clock.update_and_sync(observations)
        if result is None:
            logger.debug("[SYNC] BFT consensus not reached")
            return

        new_state = SharedClockState(
            agreed_time=result.agreed_time,
            applied_drift=result.applied_drift,
            last_updated_unix=now,
        )

        if self._store.watch_and_commit(new_state):
            logger.info(
                "[CLOCK SYNC] agreed=%d drift=%+ds accepted=%d rejected=%d",
                result.agreed_time,
                result.applied_drift,
                result.accepted_sources,
                result.rejected_sources,
            )
            self._vault.persist_ntp_sequences(self._fetcher.save_sequence_state())
            if self._on_sync:
                try:
                    self._on_sync(result)
                except Exception:
                    pass
        else:
            logger.debug("[CLOCK SYNC] Shared store commit lost race; discarding result")
