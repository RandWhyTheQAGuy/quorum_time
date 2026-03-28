"""
tests/test_clock_state.py

Unit tests for bridge/clock_state.py.
No C++ dependency.
"""

from __future__ import annotations

import threading
import time

import pytest

from bridge.clock_state import ClockState
from tests.conftest import make_attested_time


class TestClockStateBasic:
    def test_empty_get_returns_none(self, empty_state):
        assert empty_state.get() is None

    def test_empty_get_or_raise(self, empty_state):
        with pytest.raises(RuntimeError, match="not yet initialised"):
            empty_state.get_or_raise()

    def test_update_then_get(self, empty_state):
        at = make_attested_time()
        empty_state.update(at)
        result = empty_state.get()
        assert result is at

    def test_is_healthy_false_when_empty(self, empty_state):
        assert not empty_state.is_healthy()

    def test_is_healthy_true_after_update(self, populated_state):
        assert populated_state.is_healthy()

    def test_age_returns_inf_when_empty(self, empty_state):
        assert empty_state.age_seconds() == float("inf")

    def test_age_increases_over_time(self, populated_state):
        age1 = populated_state.age_seconds()
        time.sleep(0.05)
        age2 = populated_state.age_seconds()
        assert age2 > age1


class TestClockStateStaleness:
    def test_stale_is_not_healthy(self, stale_state):
        assert not stale_state.is_healthy()

    def test_stale_get_or_raise(self, stale_state):
        with pytest.raises(RuntimeError, match="stale"):
            stale_state.get_or_raise()

    def test_stale_get_still_returns_data(self, stale_state):
        # get() never raises - callers decide what to do with old data
        assert stale_state.get() is not None


class TestClockStateErrors:
    def test_error_count_starts_at_zero(self, empty_state):
        assert empty_state.error_count() == 0

    def test_record_error_increments(self, empty_state):
        empty_state.record_error()
        empty_state.record_error()
        assert empty_state.error_count() == 2

    def test_update_resets_error_count(self, empty_state):
        empty_state.record_error()
        empty_state.record_error()
        empty_state.update(make_attested_time())
        assert empty_state.error_count() == 0


class TestClockStateThreadSafety:
    def test_concurrent_updates_and_reads(self):
        state = ClockState(staleness_limit_seconds=10.0)
        errors = []

        def writer():
            for i in range(100):
                state.update(make_attested_time(unix_seconds=float(1_700_000_000 + i)))
                time.sleep(0.001)

        def reader():
            for _ in range(200):
                try:
                    at = state.get()
                    if at is not None:
                        _ = at.unix_seconds
                except Exception as exc:
                    errors.append(exc)
                time.sleep(0.0005)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        assert not errors, f"Thread safety errors: {errors}"


class TestClockStateWaitForUpdate:
    def test_wait_times_out_when_no_update(self, empty_state):
        result = empty_state.wait_for_update(timeout=0.05)
        assert result is False

    def test_wait_returns_true_on_update(self, empty_state):
        got_update = threading.Event()

        def _trigger():
            time.sleep(0.05)
            empty_state.update(make_attested_time())

        t = threading.Thread(target=_trigger)
        t.start()
        result = empty_state.wait_for_update(timeout=1.0)
        t.join()
        assert result is True
