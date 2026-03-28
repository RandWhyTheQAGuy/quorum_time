"""
bridge/formats.py

Converts a raw quorum snapshot into every output format the bridge exposes.

All four formats are derived from the same AttestedTime snapshot so they
are guaranteed to be internally consistent within a single response.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AttestedTime:
    """
    Normalised snapshot produced by the ClockState after each BFT sync.
    This is the single source of truth passed to every format encoder.
    """
    unix_seconds: float           # agreed BFT time (float for sub-second precision)
    uncertainty_ms: float         # current uncertainty window in milliseconds
    drift_ppm: float              # current drift estimate in parts-per-million
    accepted_sources: list[str]   # NTP authorities that passed quorum
    rejected_sources: list[str]   # NTP authorities that were rejected
    quorum_hash_hex: str          # hex digest of the quorum result (from vault)
    local_mono_ns: int            # local monotonic ns at time of capture (for freshness checks)

    @property
    def unix_seconds_int(self) -> int:
        return int(self.unix_seconds)

    @property
    def unix_nanos(self) -> int:
        return int(self.unix_seconds * 1_000_000_000)


# ---------------------------------------------------------------------------
# Unix epoch
# ---------------------------------------------------------------------------

def to_unix(at: AttestedTime) -> dict[str, Any]:
    """Integer seconds + nanoseconds remainder, plus uncertainty."""
    whole = int(at.unix_seconds)
    nanos = int((at.unix_seconds - whole) * 1_000_000_000)
    return {
        "unix_seconds": whole,
        "unix_nanos": nanos,
        "uncertainty_ms": at.uncertainty_ms,
    }


# ---------------------------------------------------------------------------
# ISO 8601 / RFC 3339
# ---------------------------------------------------------------------------

def to_iso8601(at: AttestedTime) -> dict[str, Any]:
    """
    RFC 3339 timestamp with microsecond resolution, always UTC (Z suffix).
    Includes uncertainty and quorum metadata for consumers that want to
    carry attestation context through their own audit trail.
    """
    dt = datetime.fromtimestamp(at.unix_seconds, tz=timezone.utc)
    return {
        "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "uncertainty_ms": at.uncertainty_ms,
        "drift_ppm": at.drift_ppm,
        "quorum_hash": at.quorum_hash_hex,
    }


# ---------------------------------------------------------------------------
# JSON envelope (full attestation)
# ---------------------------------------------------------------------------

def to_json_envelope(at: AttestedTime) -> dict[str, Any]:
    """
    Full attested envelope.  This is the richest format - intended for
    consumers that need to log or verify the quorum proof themselves.
    """
    dt = datetime.fromtimestamp(at.unix_seconds, tz=timezone.utc)
    return {
        "unix_seconds": int(at.unix_seconds),
        "unix_nanos": at.unix_nanos,
        "iso8601": dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "uncertainty_ms": at.uncertainty_ms,
        "drift_ppm": at.drift_ppm,
        "quorum": {
            "accepted_sources": list(at.accepted_sources),
            "rejected_sources": list(at.rejected_sources),
            "quorum_hash": at.quorum_hash_hex,
        },
    }


# ---------------------------------------------------------------------------
# NTP packet (RFC 5905 - 48 bytes, NTPv4)
# ---------------------------------------------------------------------------

# Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch)
_NTP_DELTA = 2_208_988_800

# LI=0 (no warning), VN=4 (NTPv4), Mode=4 (server)
_NTP_FLAGS = (0 << 6) | (4 << 3) | 4   # 0x24
_STRATUM    = 1   # primary reference (we ARE the trusted source)
_POLL       = 4   # 2^4 = 16 s nominal poll interval
_PRECISION  = -20 # ~1 µs precision (2^-20 s)


def _to_ntp_timestamp(unix_seconds: float) -> tuple[int, int]:
    """Convert Unix float seconds to (NTP seconds, NTP fraction 2^-32 units)."""
    ntp_seconds = int(unix_seconds) + _NTP_DELTA
    fraction = int((unix_seconds - int(unix_seconds)) * 2**32)
    return ntp_seconds, fraction


def to_ntp_packet(at: AttestedTime) -> bytes:
    """
    Build a 48-byte NTPv4 server response packet from an AttestedTime.

    The Transmit Timestamp is set to the agreed BFT time.
    Reference, Originate, and Receive timestamps are set to the same
    value - this is correct for a stratum-1 server that is itself the
    reference (not a relay).

    Callers are responsible for setting the Originate Timestamp field to
    the client's Transmit Timestamp before sending (standard NTP practice).
    This function produces the static server-side fields only.
    """
    ntp_sec, ntp_frac = _to_ntp_timestamp(at.unix_seconds)

    # Root delay and dispersion encoded as 16.16 fixed-point seconds
    # Uncertainty in seconds -> NTP short format
    uncertainty_sec = at.uncertainty_ms / 1000.0
    root_dispersion_ntp = int(uncertainty_sec * 65536) & 0xFFFF_FFFF

    packet = struct.pack(
        "!B B b b I I I II II II II",
        _NTP_FLAGS,          # LI/VN/Mode
        _STRATUM,            # Stratum
        _POLL,               # Poll
        _PRECISION,          # Precision (signed)
        0,                   # Root Delay (0 - we are stratum 1)
        root_dispersion_ntp, # Root Dispersion
        0x41455349,          # Reference ID "AESI" (Aegis)
        ntp_sec, ntp_frac,   # Reference Timestamp
        ntp_sec, ntp_frac,   # Originate Timestamp (will be overwritten by UDP handler)
        ntp_sec, ntp_frac,   # Receive Timestamp
        ntp_sec, ntp_frac,   # Transmit Timestamp
    )
    return packet


# ---------------------------------------------------------------------------
# Format selector (used by REST/gRPC/WS handlers)
# ---------------------------------------------------------------------------

def format_response(at: AttestedTime, fmt: str) -> dict[str, Any]:
    """
    Dispatch to the correct encoder by format name.
    'ntp' is not available here - use to_ntp_packet() directly for UDP.
    """
    fmt = fmt.lower()
    if fmt == "unix":
        return to_unix(at)
    if fmt in ("iso8601", "iso", "rfc3339"):
        return to_iso8601(at)
    if fmt in ("json", "full", "envelope"):
        return to_json_envelope(at)
    raise ValueError(f"Unknown format '{fmt}'. Valid: unix, iso8601, json")


SUPPORTED_FORMATS = ("unix", "iso8601", "json")
