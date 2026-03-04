"""
uml001.bft_clock
================
Python equivalent of bft_quorum_clock.cpp.

Byzantine Fault-Tolerant Quorum Clock for Python.

Security model
--------------
This class is the **only** component permitted to read the OS system clock
(``time.time()``).  All other SDK components obtain time by calling
``BFTQuorumTrustedClock.now_unix()``.

Security guarantees (all from the C++ implementation)
------------------------------------------------------
- Byzantine quorum consensus over trusted NTP authorities (formal PBFT math).
- Outlier trimming: F = ⌊(N-1)/3⌋ lowest and highest values discarded.
- Cluster skew enforcement: ``max_cluster_skew`` seconds maximum spread.
- Drift shock limiting: single-step adjustment capped at ``max_drift_step``.
- Drift creep ceiling: cumulative correction capped at ``max_total_drift``.
- Monotonic floor guarantee: ``now_unix()`` never goes backwards.
- Sequence replay-window tracking per authority.
- Fail-closed mode: ``abort()`` (raises ``SystemExit``) if drift ceiling exceeded.
- Audit logging via ``ColdVault``.
- Crash-recovery: persisted drift and sequences loaded from vault on start.

Classes
-------
BFTClockConfig
    Runtime-configurable parameters for the BFT clock.
BftSyncResult
    Result of a successful ``update_and_sync`` call.
BFTQuorumTrustedClock
    The main clock class.
"""

import hashlib
import hmac as _hmac
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .crypto_utils import hmac_sha256_hex, constant_time_equals
from .ntp_fetcher import TimeObservation
from .vault import ColdVault


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class BFTClockConfig:
    """Mirrors ``BFTQuorumTrustedClock::Config`` from bft_quorum_clock.h."""
    min_quorum: int = 3
    max_cluster_skew: int = 5          # seconds
    max_drift_step: int = 30           # seconds per sync
    max_total_drift: int = 3600        # seconds absolute
    sequence_ttl_seconds: int = 300
    clock_degradation_window_seconds: int = 300
    fail_closed: bool = True


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class BftSyncResult:
    """Mirrors the C++ ``BftSyncResult`` struct."""
    agreed_time: int
    applied_drift: int       # drift_step applied in this sync
    accepted_sources: int    # nodes in the BFT-trimmed cluster
    outliers_ejected: int    # nodes dropped as potential Byzantine faults
    rejected_sources: int    # nodes that failed auth / whitelist checks


# ---------------------------------------------------------------------------
# Authority registry (mirrors the C++ global authority registry)
# ---------------------------------------------------------------------------

_authority_registry: dict[str, dict] = {}   # authority_id -> {key_id -> hmac_key_hex}
_registry_lock = threading.Lock()


def register_hmac_authority(authority_id: str, hmac_key_hex: str, key_id: str = "default") -> None:
    """Register an HMAC authority so ``BFTQuorumTrustedClock`` can verify its observations.

    Mirrors ``register_hmac_authority`` from crypto_utils.h.

    Parameters
    ----------
    authority_id:
        Hostname / identifier used in ``TimeObservation.authority_id``.
    hmac_key_hex:
        64-hex-char HMAC key shared with the ``NtpObservationFetcher``.
    key_id:
        Key generation identifier (supports zero-downtime rotation).
    """
    with _registry_lock:
        if authority_id not in _authority_registry:
            _authority_registry[authority_id] = {}
        _authority_registry[authority_id][key_id] = hmac_key_hex


def clear_authority_registry() -> None:
    """Remove all registered authorities (useful in tests)."""
    with _registry_lock:
        _authority_registry.clear()


def crypto_verify(payload: str, signature: str, authority_id: str, key_id: str = "default") -> bool:
    """Verify an HMAC-SHA-256 signature for *authority_id* / *key_id*.

    Mirrors the C++ ``crypto_verify`` dispatch function.  Returns ``False``
    if the authority is not registered or the MAC does not match.
    """
    with _registry_lock:
        keys = _authority_registry.get(authority_id)
        if not keys:
            return False
        key_hex = keys.get(key_id)
        if not key_hex:
            return False
    expected = hmac_sha256_hex(payload, key_hex)
    return constant_time_equals(expected.encode(), signature.encode())


# ---------------------------------------------------------------------------
# BFTQuorumTrustedClock
# ---------------------------------------------------------------------------

class BFTQuorumTrustedClock:
    """Byzantine Fault-Tolerant Trusted Clock.

    Mirrors ``BFTQuorumTrustedClock`` from bft_quorum_clock.cpp.

    Construction recovers drift and sequence state from *vault* to prevent
    rollback attacks across process restarts.

    Parameters
    ----------
    config:
        ``BFTClockConfig`` instance.
    trusted_authorities:
        Set of authority IDs (hostnames) to accept.  Matches the C++
        ``trusted_authorities_`` whitelist.
    vault:
        ``ColdVault`` instance for audit logging and state persistence.
    """

    def __init__(
        self,
        config: BFTClockConfig,
        trusted_authorities: set[str],
        vault: ColdVault,
    ) -> None:
        self._config = config
        self._trusted_authorities = set(trusted_authorities)
        self._vault = vault

        self._lock = threading.Lock()

        # Recover persisted drift (prevents rollback attacks across restarts)
        self._current_drift: int = vault.load_last_drift() or 0

        # Recover sequence map (prevents cross-restart replay attacks)
        self._authority_sequences: dict[str, int] = vault.load_authority_sequences()

        # Monotonic floor (SEC-001)
        self._last_monotonic_read: int = 0

    # ------------------------------------------------------------------
    # IStrongClock
    # ------------------------------------------------------------------

    def now_unix(self) -> int:
        """Return BFT-corrected Unix timestamp.

        SEC-001: The returned value is guaranteed never to decrease within
        a process lifetime (monotonic floor guarantee).
        """
        with self._lock:
            raw_os_time = int(time.time())
            secure_time = raw_os_time + self._current_drift
            if secure_time < self._last_monotonic_read:
                secure_time = self._last_monotonic_read
            else:
                self._last_monotonic_read = secure_time
            return secure_time

    def get_current_drift(self) -> int:
        """Return the current drift offset in seconds."""
        with self._lock:
            return self._current_drift

    # ------------------------------------------------------------------
    # Observation verification
    # ------------------------------------------------------------------

    def _verify_observation(self, obs: TimeObservation) -> bool:
        """Authenticate and validate a single ``TimeObservation``.

        Checks (in order):
        1. Authority whitelist
        2. Sequence monotonicity (replay detection)
        3. HMAC-SHA-256 signature via registered key
        """
        # 1. Authority whitelist
        if obs.authority_id not in self._trusted_authorities:
            return False

        # 2. Replay-window check
        last_seq = self._authority_sequences.get(obs.authority_id, 0)
        if obs.sequence <= last_seq:
            return False

        # 3. Signature verification
        # Canonical payload: authority_id|key_id|timestamp|sequence
        payload = f"{obs.authority_id}|{obs.key_id}|{obs.timestamp}|{obs.sequence}"
        return crypto_verify(payload, obs.signature, obs.authority_id, obs.key_id)

    # ------------------------------------------------------------------
    # BFT synchronisation
    # ------------------------------------------------------------------

    def update_and_sync(
        self, observations: list[TimeObservation]
    ) -> Optional[BftSyncResult]:
        """Run a full BFT consensus round over *observations*.

        Steps:
        1. Verify signatures, whitelist, and replay windows.
        2. Sort and apply formal Byzantine trimming (F = ⌊(N-1)/3⌋).
        3. Validate cluster skew.
        4. Compute median agreed time.
        5. Compute and clamp drift adjustment.
        6. Commit drift and replay-window state.
        7. Write audit log entry.

        Returns ``None`` if quorum cannot be achieved or constraints are
        violated.  In ``fail_closed`` mode, raises ``SystemExit`` if the
        drift ceiling is exceeded (matching C++ ``std::abort()``).
        """
        valid_timestamps: list[int] = []
        valid_observations: list[TimeObservation] = []
        rejected = 0

        # Step 1 – verify
        for obs in observations:
            if self._verify_observation(obs):
                valid_timestamps.append(obs.timestamp)
                valid_observations.append(obs)
            else:
                rejected += 1

        n_valid = len(valid_timestamps)
        if n_valid < self._config.min_quorum:
            return None

        # Step 2 – sort + BFT trimming
        valid_timestamps.sort()

        # PBFT: F = ⌊(N-1)/3⌋
        f_tolerance = (n_valid - 1) // 3 if n_valid > 0 else 0
        if n_valid < 3 * f_tolerance + 1:
            return None

        # Drop F lowest and F highest (potential Byzantine)
        if f_tolerance > 0:
            clustered = valid_timestamps[f_tolerance:-f_tolerance]
        else:
            clustered = valid_timestamps[:]

        if not clustered:
            return None

        # Step 3 – cluster skew
        if clustered[-1] - clustered[0] > self._config.max_cluster_skew:
            return None

        # Step 4 – median
        n = len(clustered)
        if n % 2 == 0:
            agreed_time = (clustered[n // 2 - 1] + clustered[n // 2]) // 2
        else:
            agreed_time = clustered[n // 2]

        # Step 5 – drift computation
        raw_os_time = int(time.time())
        target_drift = agreed_time - raw_os_time
        drift_step = target_drift - self._current_drift

        # Anti-shock clamp
        max_step = self._config.max_drift_step
        if abs(drift_step) > max_step:
            drift_step = max_step if drift_step > 0 else -max_step

        proposed_total = self._current_drift + drift_step

        # Anti-creep ceiling
        if abs(proposed_total) > self._config.max_total_drift:
            if self._config.fail_closed:
                raise SystemExit(
                    "[BFT CLOCK] Total drift ceiling exceeded – fail_closed=True"
                )
            return None

        # Step 6 – commit
        with self._lock:
            self._current_drift = proposed_total
            for obs in valid_observations:
                self._authority_sequences[obs.authority_id] = obs.sequence

        # Step 7 – audit
        self._vault.log_sync_event(agreed_time, drift_step, self._current_drift)
        self._vault.save_authority_sequences(self._authority_sequences)

        return BftSyncResult(
            agreed_time=agreed_time,
            applied_drift=drift_step,
            accepted_sources=len(clustered),
            outliers_ejected=len(valid_timestamps) - len(clustered),
            rejected_sources=rejected,
        )

    # ------------------------------------------------------------------
    # Shared-state adoption (clustered deployment)
    # ------------------------------------------------------------------

    def apply_shared_state(
        self,
        shared_agreed_time: int,
        shared_applied_drift: int,
        leader_system_time_at_sync: int = 0,
    ) -> bool:
        """Adopt BFT consensus state from another cluster node.

        Mirrors ``BFTQuorumTrustedClock::apply_shared_state`` from
        bft_quorum_clock.cpp.

        Applies the same shock and creep guards as ``update_and_sync``.
        Returns ``True`` if the state was accepted, ``False`` if it was
        rejected by a guard constraint.

        Parameters
        ----------
        shared_agreed_time:
            BFT-agreed Unix timestamp from the leading node.
        shared_applied_drift:
            Drift step that was applied on the leading node.
        leader_system_time_at_sync:
            The leader's ``time.time()`` at the moment of the BFT round.
            Used to correct for transmission latency.  Pass 0 to skip.
        """
        local_raw_os_time = int(time.time())

        if leader_system_time_at_sync > 0:
            os_delta = local_raw_os_time - leader_system_time_at_sync
            expected_now = shared_agreed_time + os_delta
        else:
            expected_now = shared_agreed_time

        proposed_drift = expected_now - local_raw_os_time
        drift_step = proposed_drift - self._current_drift

        max_step = self._config.max_drift_step
        if abs(drift_step) > max_step:
            drift_step = max_step if drift_step > 0 else -max_step

        safe_total = self._current_drift + drift_step
        if abs(safe_total) > self._config.max_total_drift:
            return False

        with self._lock:
            self._current_drift = safe_total

        self._vault.log_sync_event(expected_now, drift_step, self._current_drift)
        return True
