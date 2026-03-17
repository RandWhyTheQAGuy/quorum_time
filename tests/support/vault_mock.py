# support/vault_mock.py
#
# MockVault: in-memory vault for local development and pytest fixtures.
#
# Provides the same observable interface as ColdVault without requiring
# a real filesystem or C++ backend. All writes are captured in-memory
# and exposed as typed lists for straightforward test assertions.
#
# Design principles:
#   - Zero trust: every write is recorded; no events are silently dropped
#   - Auditability: security_events, sync_events, and the raw log are all
#     independently inspectable
#   - Cold-start fidelity: drift and sequences survive within a test session
#     and can be pre-seeded to simulate recovery from a prior run
#   - Read-back safety: uses SimpleFileVaultBackend for on-disk audit writes
#     so that backend.read_all() / read_last_line() reflect real file state
#   - No side effects: does not touch production vault files or global state
#
# Compatibility:
#   - Used by the fixture-based pytest test (test_bft_clock_fixture.py)
#   - Compatible with ColdVault constructor:
#       uml001.ColdVault(config, backend, clock, hashp)
#   - MockVault is NOT passed directly to ColdVault; it is the Python-side
#     inspection handle. The C++ ColdVault receives the underlying backend.

import tempfile
import os
from typing import Dict, List, Optional


class MockVault:
    """
    In-memory vault suitable for pytest fixtures and local development.

    Attributes inspectable by tests:
        security_events  — list of {"key": str, "detail": str} dicts
        sync_events      — list of {"agreed_time": int, "step": int,
                                    "total_drift": int} dicts
        sequences        — dict mapping authority hostname -> last sequence
        drift            — last saved drift value (int, default 0)
        log              — raw list of all appended line strings

    Backend:
        The underlying SimpleFileVaultBackend is accessible via .backend
        so that tests can call backend.read_all() / read_last_line() and
        assert against real on-disk audit content.
    """

    def __init__(self, initial_drift: int = 0, tmp_dir: Optional[str] = None):
        """
        Construct a MockVault.

        Args:
            initial_drift: Simulated pre-existing drift (for cold-start tests).
            tmp_dir:        Optional directory for the audit file. If None, a
                            temporary directory is created automatically and
                            cleaned up when the MockVault is garbage collected.
        """
        # Cold-start state
        self.drift: int = initial_drift
        self.sequences: Dict[str, int] = {}

        # Audit capture — independently inspectable by test assertions
        self.security_events: List[dict] = []
        self.sync_events: List[dict] = []
        self.log: List[str] = []

        # Filesystem backend for on-disk audit fidelity
        # A temporary directory is used so tests remain isolated
        self._owns_tmp = tmp_dir is None
        self._tmp_dir = tmp_dir or tempfile.mkdtemp(prefix="mock_vault_")

        # Defer import to avoid circular dependency at module load time
        import uml001
        self.backend = uml001.SimpleFileVaultBackend(self._tmp_dir)

    def __del__(self):
        """Clean up the temporary directory if we created it."""
        if self._owns_tmp and os.path.isdir(self._tmp_dir):
            import shutil
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # ColdVault-compatible API
    #
    # These methods mirror what ColdVault exposes to BFTQuorumTrustedClock.
    # They write to both the in-memory log and the on-disk backend so that
    # assertions against either surface are always consistent.
    # ------------------------------------------------------------------

    def log_security_event(self, key: str, detail: str) -> None:
        """
        Record a security event.

        Captured in self.security_events for structured assertions, and
        appended to the on-disk audit log for read_all() / read_last_line().
        """
        entry = {"key": key, "detail": detail}
        self.security_events.append(entry)

        line = f"security_event key={key} detail={detail}"
        self.log.append(line)
        self.backend.append_line(line)

    def log_sync_event(self,
                       agreed_time: int,
                       step: int,
                       total_drift: int) -> None:
        """
        Record a successful BFT sync round.

        Captured in self.sync_events for structured assertions, and
        appended to the on-disk audit log. The line contains the token
        "bft.sync.committed" so that raw log scans match production format.
        """
        entry = {
            "agreed_time": agreed_time,
            "step":        step,
            "total_drift": total_drift,
        }
        self.sync_events.append(entry)

        line = (
            f"bft.sync.committed agreed_time={agreed_time} "
            f"step={step} total_drift={total_drift}"
        )
        self.log.append(line)
        self.backend.append_line(line)

    def log_key_rotation_event(self,
                                key_version: int,
                                unix_time: int) -> None:
        """
        Record a key rotation event in the audit log.

        Not captured in a typed list (key rotation is rare and does not
        require structured inspection in current tests), but written to
        the on-disk log for auditability.
        """
        line = f"key_rotation version={key_version} unix_time={unix_time}"
        self.log.append(line)
        self.backend.append_line(line)

    # ------------------------------------------------------------------
    # Drift persistence (cold-start recovery simulation)
    # ------------------------------------------------------------------

    def save_last_drift(self, drift: int) -> None:
        """Persist drift value for cold-start recovery."""
        self.drift = drift

    def load_last_drift(self) -> Optional[int]:
        """
        Load the last persisted drift.

        Returns None if no drift has been saved (mirrors ColdVault behavior
        on a fresh vault with no prior state).
        """
        return self.drift if self.drift is not None else None

    # ------------------------------------------------------------------
    # Sequence persistence (replay-attack prevention)
    # ------------------------------------------------------------------

    def save_authority_sequences(self, sequences: Dict[str, int]) -> None:
        """Persist per-authority sequence numbers."""
        self.sequences = dict(sequences)

    def load_authority_sequences(self) -> Dict[str, int]:
        """
        Load persisted authority sequence numbers.

        Returns an empty dict on a fresh vault (mirrors ColdVault behavior).
        """
        return dict(self.sequences)

    # ------------------------------------------------------------------
    # Inspection helpers (test convenience, not part of ColdVault API)
    # ------------------------------------------------------------------

    def read_all(self) -> List[str]:
        """
        Return all lines written to the in-memory log.

        This is the MockVault-side equivalent of backend.read_all().
        Both should be consistent; use backend.read_all() when testing
        the on-disk audit path, and this when testing in-memory capture.
        """
        return list(self.log)

    def clear(self) -> None:
        """
        Reset all in-memory state.

        Useful for multi-round tests that need a clean slate between
        assertions without constructing a new MockVault.
        Does NOT clear the on-disk audit file — call backend.rotate()
        separately if on-disk isolation is also required.
        """
        self.security_events.clear()
        self.sync_events.clear()
        self.log.clear()
        self.drift = 0
        self.sequences.clear()