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
uml001.vault
============
Python equivalents of cold_vault.cpp and file_vault_backend.cpp.

Classes
-------
VaultConfig
    Configuration for ColdVault (base directory, size/age rotation limits).
IVaultBackend (ABC)
    Abstract backend interface (``append_line``, ``read_last_line``, ``rotate``).
FileVaultBackend
    Append-only file backend with optional fsync, archival, and rotation.
    Mirrors ``FileVaultBackend`` from file_vault_backend.cpp.
ColdVault
    Hash-chained append-only audit log with drift-state persistence.
    Mirrors ``ColdVault`` from cold_vault.cpp.

The ``IStrongClock`` interface is satisfied by any object with a
``now_unix() -> int`` method; in production this is a ``BFTQuorumTrustedClock``
instance.  For testing, a simple lambda or ``MockClock`` works.
"""

import os
import shutil
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .crypto_utils import sha256_hex


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class VaultConfig:
    """Mirrors the C++ ``ColdVault::Config`` struct."""
    base_directory: str | Path = "var/uml001/vault"
    max_file_size_bytes: int = 64 * 1024 * 1024   # 64 MB
    max_file_age_seconds: int = 86400              # 24 h
    fsync_on_write: bool = True


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

class IVaultBackend(ABC):
    """Abstract vault storage backend.  Mirrors ``IVaultBackend`` from vault.h."""

    @abstractmethod
    def append_line(self, line: str) -> None:
        """Append a single newline-terminated log line."""

    @abstractmethod
    def read_last_line(self) -> Optional[str]:
        """Return the last line of the current log file, or None if empty."""

    @abstractmethod
    def rotate(self) -> None:
        """Archive the current file and open a fresh one."""


# ---------------------------------------------------------------------------
# File backend
# ---------------------------------------------------------------------------

class FileVaultBackend(IVaultBackend):
    """Append-only file vault backend.

    Mirrors ``FileVaultBackend`` from file_vault_backend.cpp.

    Files are named ``vault_<unix_ts>.log`` inside *base_dir*.
    On rotation the active file is moved to ``<base_dir>/archive/``.
    When *fsync_on_write* is True, ``os.fsync`` is called after each write
    (equivalent to the C++ ``fdatasync`` path).

    Parameters
    ----------
    base_dir:
        Root directory for vault files.  Created if it does not exist.
    fsync_on_write:
        Flush to durable storage after every append.
    clock:
        Any object with a ``now_unix() -> int`` method used to timestamp
        new vault filenames.
    """

    def __init__(
        self,
        base_dir: str | Path,
        fsync_on_write: bool = True,
        clock=None,
    ) -> None:
        self._base_dir = Path(base_dir)
        self._fsync_on_write = fsync_on_write
        self._clock = clock

        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._active_file: Optional[Path] = None
        self._fh = None
        self._open_new_file()

    # ------------------------------------------------------------------
    # IVaultBackend
    # ------------------------------------------------------------------

    def append_line(self, line: str) -> None:
        if not line.endswith("\n"):
            line += "\n"
        self._fh.write(line)
        self._fh.flush()
        if self._fsync_on_write:
            os.fsync(self._fh.fileno())

    def read_last_line(self) -> Optional[str]:
        if self._active_file is None or not self._active_file.exists():
            return None
        last = None
        try:
            with open(self._active_file, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.rstrip("\n")
                    if stripped:
                        last = stripped
        except OSError:
            return None
        return last

    def rotate(self) -> None:
        self._archive_current()
        self._open_new_file()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now_unix(self) -> int:
        if self._clock is not None:
            return self._clock.now_unix()
        import time
        return int(time.time())

    def _open_new_file(self) -> None:
        ts = self._now_unix()
        self._active_file = self._base_dir / f"vault_{ts}.log"
        # pylint: disable=consider-using-with
        self._fh = open(self._active_file, "a", encoding="utf-8")

    def _archive_current(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
        if self._active_file and self._active_file.exists():
            archive_dir = self._base_dir / "archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            dest = archive_dir / self._active_file.name
            shutil.move(str(self._active_file), str(dest))
        self._active_file = None

    def close(self) -> None:
        """Close the active file handle gracefully."""
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ColdVault
# ---------------------------------------------------------------------------

class ColdVault:
    """Hash-chained append-only audit log with BFT drift-state persistence.

    Mirrors ``ColdVault`` from cold_vault.cpp.

    Each entry is a single text line of the form::

        ts=<unix> agreed=<u64> drift_step=<i64> total_drift=<i64>
        prev_hash=<hex> hash=<sha256_of_content>

    The ``hash`` field is SHA-256 over the entire line content preceding it,
    and each entry's ``prev_hash`` points to the previous entry's hash,
    forming a tamper-evident chain.  This mirrors the C++ implementation's
    ``build_log_entry`` method.

    Parameters
    ----------
    config:
        ``VaultConfig`` controlling rotation limits.
    backend:
        Storage backend (default: ``FileVaultBackend``).
    clock:
        Strong-clock provider with ``now_unix() -> int``.  If ``None``,
        falls back to ``time.time()``.
    """

    def __init__(
        self,
        config: Optional[VaultConfig] = None,
        backend: Optional[IVaultBackend] = None,
        clock=None,
    ) -> None:
        self._config = config or VaultConfig()
        self._clock = clock
        self._lock = threading.Lock()

        base_dir = Path(self._config.base_directory)
        base_dir.mkdir(parents=True, exist_ok=True)

        self._backend = backend or FileVaultBackend(
            base_dir=base_dir,
            fsync_on_write=self._config.fsync_on_write,
            clock=clock,
        )

        self._current_file_start_time: int = self._now()
        self._current_file_size: int = 0

        # Recover last hash from existing log (chain continuity)
        last_line = self._backend.read_last_line()
        if last_line:
            idx = last_line.find("hash=")
            self._last_hash: str = last_line[idx + 5:] if idx != -1 else "GENESIS"
        else:
            self._last_hash = "GENESIS"

    # ------------------------------------------------------------------
    # Public API – mirroring ColdVault methods
    # ------------------------------------------------------------------

    def log_sync_event(
        self,
        agreed_time: int,
        drift_step: int,
        total_drift: int,
    ) -> None:
        """Append a BFT clock synchronisation event to the vault.

        Thread-safe.  May trigger a file rotation if size or age limits
        are exceeded.
        """
        with self._lock:
            self._maybe_rotate()
            entry = self._build_log_entry(agreed_time, drift_step, total_drift)
            self._backend.append_line(entry)
            self._current_file_size += len(entry.encode("utf-8"))

    def load_last_drift(self) -> Optional[int]:
        """Read the ``total_drift`` field from the last vault entry.

        Returns ``None`` if no entries exist yet.
        """
        last = self._backend.read_last_line()
        if last is None:
            return None
        idx = last.find("total_drift=")
        if idx == -1:
            return None
        rest = last[idx + 12:].split()[0]  # stop at first whitespace
        try:
            return int(rest)
        except ValueError:
            return None

    def load_authority_sequences(self) -> dict[str, int]:
        """Reconstruct authority sequence numbers from vault.

        Scans all log lines for ``seq:<authority_id>=<seq>`` tokens written
        by ``save_authority_sequences``.  Returns the latest value seen per
        authority.
        """
        sequences: dict[str, int] = {}
        base_dir = Path(self._config.base_directory)
        log_files = sorted(base_dir.glob("vault_*.log"))
        for path in log_files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        for token in line.split():
                            if token.startswith("seq:") and "=" in token:
                                _, rest = token.split(":", 1)
                                auth, seq_str = rest.rsplit("=", 1)
                                try:
                                    sequences[auth] = int(seq_str)
                                except ValueError:
                                    pass
            except OSError:
                continue
        return sequences

    def save_authority_sequences(self, sequences: dict[str, int]) -> None:
        """Persist authority sequence numbers as a vault entry.

        Encodes sequences as ``seq:<authority>=<n>`` tokens so they survive
        process restarts (preventing cross-restart replay attacks).
        """
        tokens = " ".join(f"seq:{auth}={seq}" for auth, seq in sequences.items())
        with self._lock:
            self._maybe_rotate()
            ts = self._now()
            content = f"ts={ts} SEQ_SNAPSHOT {tokens} prev_hash={self._last_hash}"
            entry_hash = sha256_hex(content)
            self._last_hash = entry_hash
            line = content + f" hash={entry_hash}"
            self._backend.append_line(line)
            self._current_file_size += len(line.encode("utf-8"))

    def persist_ntp_sequences(self, sequences: dict[str, int]) -> None:
        """Alias for ``save_authority_sequences``.

        Called by the background sync loop after a successful BFT round-trip,
        matching the C++ ``vault.persist_ntp_sequences(...)`` call in
        main_ntp.cpp.
        """
        self.save_authority_sequences(sequences)

    def load_ntp_sequences(self) -> dict[str, int]:
        """Alias for ``load_authority_sequences``."""
        return self.load_authority_sequences()

    def verify_chain(self) -> bool:
        """Verify the SHA-256 hash chain across all vault log files.

        Returns ``True`` if every entry's ``hash`` field matches the
        SHA-256 of its content, and ``prev_hash`` matches the prior entry.
        Returns ``False`` on any discrepancy.
        """
        base_dir = Path(self._config.base_directory)
        log_files = sorted(base_dir.glob("vault_*.log"))
        prev_hash = "GENESIS"
        for path in log_files:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for raw in f:
                        line = raw.rstrip("\n")
                        if not line:
                            continue
                        hash_idx = line.rfind(" hash=")
                        if hash_idx == -1:
                            return False
                        content = line[:hash_idx]
                        stored_hash = line[hash_idx + 6:]
                        computed = sha256_hex(content)
                        if computed != stored_hash:
                            return False
                        # Check prev_hash linkage
                        ph_idx = content.find("prev_hash=")
                        if ph_idx != -1:
                            ph_val = content[ph_idx + 10:].split()[0]
                            if ph_val != prev_hash:
                                return False
                        prev_hash = stored_hash
            except OSError:
                return False
        return True

    def close(self) -> None:
        """Close the backend gracefully."""
        if hasattr(self._backend, "close"):
            self._backend.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now(self) -> int:
        if self._clock is not None:
            return self._clock.now_unix()
        import time
        return int(time.time())

    def _build_log_entry(
        self,
        agreed_time: int,
        drift_step: int,
        total_drift: int,
    ) -> str:
        ts = self._now()
        content = (
            f"ts={ts} agreed={agreed_time} drift_step={drift_step} "
            f"total_drift={total_drift} prev_hash={self._last_hash}"
        )
        entry_hash = sha256_hex(content)
        self._last_hash = entry_hash
        return content + f" hash={entry_hash}"

    def _maybe_rotate(self) -> None:
        """Rotate the log file if size or age limits are exceeded."""
        now = self._now()
        age = now - self._current_file_start_time
        if (
            self._current_file_size >= self._config.max_file_size_bytes
            or age >= self._config.max_file_age_seconds
        ):
            self._backend.rotate()
            self._current_file_start_time = now
            self._current_file_size = 0
            self._last_hash = "ROTATE_BOUNDARY"
