"""
uml001.ntp_fetcher
==================
Python equivalent of ntp_observation_fetcher.cpp.

Queries a pool of NTP servers concurrently, applies HMAC-SHA-256
signatures to each raw observation, and returns ``TimeObservation``
objects ready for BFT consensus.

Classes
-------
NtpServerEntry
    Configuration for one NTP server (hostname, port, timeouts).
NtpObservation
    Raw data returned by a single NTP server query.
TimeObservation
    Signed observation passed to ``BFTQuorumTrustedClock.update_and_sync``.
NtpObservationFetcher
    Concurrent NTP fetcher with HMAC signing and sequence-replay protection.

NTP protocol notes
------------------
- Packet: 48-byte client request, byte 0 = 0x23 (LI=0, VN=4, Mode=3).
- Transmit Timestamp: bytes 40-43 (big-endian uint32, NTP seconds since 1900).
- Stratum: byte 1.
- NTP epoch offset: 2208988800 seconds (1900-01-01 → 1970-01-01).
- RTT correction: applied if round-trip >= 2 s (rarely triggered).

Security
--------
Each observation is HMAC-SHA-256 signed with the shared *hmac_key* so that
``BFTQuorumTrustedClock.verify_observation`` can authenticate it without an
external PKI.  Sequence numbers prevent cross-restart replay attacks.
"""

import hashlib
import hmac
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass, field
from typing import Optional

from .crypto_utils import hmac_sha256_hex, generate_random_bytes_hex


# ---------------------------------------------------------------------------
# Constants (mirror C++ constexpr values)
# ---------------------------------------------------------------------------

_NTP_UNIX_OFFSET: int = 2_208_988_800    # seconds between 1900 and 1970
_NTP_PACKET_SIZE: int = 48
_NTP_CLIENT_BYTE0: int = 0x23            # LI=0, VN=4, Mode=3
_NTP_TRANSMIT_TS_OFFSET: int = 40
_NTP_STRATUM_OFFSET: int = 1


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NtpServerEntry:
    """Configuration for a single NTP server.

    Mirrors the C++ ``NtpServerEntry`` struct.
    """
    hostname: str
    port: int = 123
    nts_capable: bool = False
    timeout_ms: int = 2000
    max_rtt_ms: int = 500

    @staticmethod
    def default_pool() -> list["NtpServerEntry"]:
        """Return the same default server pool as the C++ implementation."""
        return [
            NtpServerEntry("time.cloudflare.com", nts_capable=True,  timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.google.com",     nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.windows.com",    nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.apple.com",      nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.nist.gov",       nts_capable=False, timeout_ms=3000, max_rtt_ms=800),
        ]


@dataclass
class NtpObservation:
    """Raw result from a single NTP server query.

    Mirrors the C++ ``NtpObservation`` struct.
    """
    server_hostname: str
    unix_seconds: int
    rtt_ms: int
    stratum: int
    nts_authenticated: bool = False


@dataclass
class TimeObservation:
    """Signed, sequenced NTP observation ready for BFT consensus.

    Mirrors the C++ ``TimeObservation`` struct (bft_quorum_clock.h).
    """
    authority_id: str
    timestamp: int
    signature: str       # HMAC-SHA-256 hex over "authority_id|timestamp|sequence"
    sequence: int
    key_id: str = "default"   # supports key-rotation dispatch


# ---------------------------------------------------------------------------
# NtpObservationFetcher
# ---------------------------------------------------------------------------

class NtpObservationFetcher:
    """Concurrent NTP observation fetcher with HMAC signing.

    Mirrors ``NtpObservationFetcher`` from ntp_observation_fetcher.cpp.

    Parameters
    ----------
    hmac_key_hex:
        64-hex-char (32-byte) HMAC key shared with ``BFTQuorumTrustedClock``.
    servers:
        NTP server pool.  Defaults to ``NtpServerEntry.default_pool()``.
    stratum_max:
        Maximum accepted stratum (1 = primary, 2 = secondary, 3 = relay).
        Mirrors the C++ ``stratum_max_`` field.
    max_workers:
        Maximum concurrent NTP query threads.
    """

    def __init__(
        self,
        hmac_key_hex: str,
        servers: Optional[list[NtpServerEntry]] = None,
        stratum_max: int = 3,
        max_workers: int = 10,
    ) -> None:
        if not hmac_key_hex:
            raise ValueError("hmac_key_hex must not be empty")
        servers = servers or NtpServerEntry.default_pool()
        if not servers:
            raise ValueError("server pool must not be empty")

        self._hmac_key_hex = hmac_key_hex
        self._servers = servers
        self._stratum_max = stratum_max
        self._max_workers = max_workers

        self._seq_lock = threading.Lock()
        # Initialise sequence counter to 0 for each server (mirrors C++ init loop)
        self._sequences: dict[str, int] = {s.hostname: 0 for s in servers}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch(self) -> list[TimeObservation]:
        """Query all NTP servers concurrently and return signed observations.

        Servers that time out, return an invalid stratum, or exceed the
        max RTT are silently dropped (mirrors the C++ ``fetch()`` behaviour).
        """
        observations: list[TimeObservation] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures: dict[Future, NtpServerEntry] = {
                pool.submit(self._query_server, s): s for s in self._servers
            }
            for future in as_completed(futures):
                try:
                    raw = future.result()
                    if raw is not None:
                        observations.append(self._sign_observation(raw))
                except Exception:
                    # Silent drop – mirrors C++ catch(...) in fetch()
                    pass
        return observations

    def load_sequence_state(self, state: dict[str, int]) -> None:
        """Restore persisted sequence numbers from a prior run.

        Called after loading from ``ColdVault`` to prevent cross-restart
        replay attacks.
        """
        with self._seq_lock:
            for hostname, seq in state.items():
                if hostname in self._sequences:
                    self._sequences[hostname] = seq

    def save_sequence_state(self) -> dict[str, int]:
        """Return a copy of the current sequence-number map for persistence."""
        with self._seq_lock:
            return dict(self._sequences)

    # ------------------------------------------------------------------
    # Internal: NTP query
    # ------------------------------------------------------------------

    def _query_server(self, server: NtpServerEntry) -> Optional[NtpObservation]:
        """Perform a single NTP UDP query.  Returns None on any failure."""
        timeout_s = server.timeout_ms / 1000.0

        try:
            # Resolve hostname
            info = socket.getaddrinfo(
                server.hostname,
                server.port,
                socket.AF_UNSPEC,
                socket.SOCK_DGRAM,
            )
            if not info:
                return None

            af, socktype, proto, _, addr = info[0]

            with socket.socket(af, socktype, proto) as sock:
                sock.settimeout(timeout_s)

                # Build 48-byte NTP client request
                packet = bytearray(_NTP_PACKET_SIZE)
                packet[0] = _NTP_CLIENT_BYTE0

                t1 = time.monotonic()
                sock.sendto(bytes(packet), addr)
                response, _ = sock.recvfrom(_NTP_PACKET_SIZE)
                t4 = time.monotonic()

                if len(response) < _NTP_PACKET_SIZE:
                    return None

                stratum = response[_NTP_STRATUM_OFFSET]
                if stratum == 0 or stratum > self._stratum_max:
                    return None

                # Extract transmit timestamp (big-endian uint32 at offset 40)
                ntp_seconds: int = struct.unpack_from("!I", response, _NTP_TRANSMIT_TS_OFFSET)[0]
                if ntp_seconds < _NTP_UNIX_OFFSET:
                    return None

                server_unix = ntp_seconds - _NTP_UNIX_OFFSET
                rtt_ms = int((t4 - t1) * 1000)

                if rtt_ms > server.max_rtt_ms:
                    return None

                # RTT correction (mirrors C++ logic exactly)
                corrected_unix = server_unix
                if rtt_ms >= 2000:
                    half_rtt_s = rtt_ms // 2000
                    corrected_unix = (
                        server_unix - half_rtt_s if server_unix > half_rtt_s else 0
                    )

                return NtpObservation(
                    server_hostname=server.hostname,
                    unix_seconds=corrected_unix,
                    rtt_ms=rtt_ms,
                    stratum=stratum,
                    nts_authenticated=False,
                )

        except (socket.timeout, socket.gaierror, OSError):
            return None

    # ------------------------------------------------------------------
    # Internal: signing
    # ------------------------------------------------------------------

    def _sign_observation(self, raw: NtpObservation) -> TimeObservation:
        """Attach a monotonic sequence number and HMAC-SHA-256 signature."""
        with self._seq_lock:
            self._sequences[raw.server_hostname] = (
                self._sequences.get(raw.server_hostname, 0) + 1
            )
            seq = self._sequences[raw.server_hostname]

        payload = f"{raw.server_hostname}|{raw.unix_seconds}|{seq}"
        signature = hmac_sha256_hex(payload, self._hmac_key_hex)

        return TimeObservation(
            authority_id=raw.server_hostname,
            timestamp=raw.unix_seconds,
            signature=signature,
            sequence=seq,
        )
