"""
bridge/clock_state.py

Thread-safe shared state between the background poll loop and all
protocol adapters.  The adapters never touch the BFT clock directly -
they read from this cache, which the poll loop refreshes on every tick.

This decouples consumer latency entirely from BFT quorum round-trip time.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from .formats import AttestedTime

logger = logging.getLogger(__name__)


class ClockState:
    """
    Holds the most recently agreed AttestedTime and exposes a threading.Event
    so WebSocket push tasks can wake on new data rather than polling.
    """

    def __init__(self, staleness_limit_seconds: float = 10.0) -> None:
        self._lock = threading.RLock()
        self._current: Optional[AttestedTime] = None
        self._updated_at_mono: float = 0.0
        self._staleness_limit = staleness_limit_seconds
        self._update_event = threading.Event()
        self._error_count: int = 0

    # ------------------------------------------------------------------
    # Write path (poll loop only)
    # ------------------------------------------------------------------

    def update(self, at: AttestedTime) -> None:
        with self._lock:
            self._current = at
            self._updated_at_mono = time.monotonic()
            self._error_count = 0
        self._update_event.set()
        self._update_event.clear()

    def record_error(self) -> None:
        with self._lock:
            self._error_count += 1

    # ------------------------------------------------------------------
    # Read path (adapters)
    # ------------------------------------------------------------------

    def get(self) -> Optional[AttestedTime]:
        """Return the current AttestedTime, or None if never populated."""
        with self._lock:
            return self._current

    def get_or_raise(self) -> AttestedTime:
        """
        Return the current AttestedTime.
        Raises RuntimeError if never populated or stale beyond the limit.
        """
        with self._lock:
            if self._current is None:
                raise RuntimeError("Clock not yet initialised - no quorum result available")
            age = time.monotonic() - self._updated_at_mono
            if age > self._staleness_limit:
                raise RuntimeError(
                    f"Clock data is stale ({age:.1f}s old, limit {self._staleness_limit}s)"
                )
            return self._current

    def is_healthy(self) -> bool:
        with self._lock:
            if self._current is None:
                return False
            age = time.monotonic() - self._updated_at_mono
            return age <= self._staleness_limit

    def error_count(self) -> int:
        with self._lock:
            return self._error_count

    def wait_for_update(self, timeout: float = 2.0) -> bool:
        """Block until the next update fires or timeout expires. Returns True on update."""
        return self._update_event.wait(timeout=timeout)

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def age_seconds(self) -> float:
        with self._lock:
            if self._current is None:
                return float("inf")
            return time.monotonic() - self._updated_at_mono
