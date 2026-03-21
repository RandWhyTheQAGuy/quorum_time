"""
uml001.ntp_fetcher
==================
Python equivalent of ntp_observation_fetcher.cpp.
"""

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from dataclasses import dataclass
from typing import Optional, List

from .crypto_utils import hmac_sha256_hex

# ---------------------------------------------------------------------------
# Constants (mirror C++ constexpr values)
# ---------------------------------------------------------------------------
_NTP_UNIX_OFFSET: int = 2_208_988_800    # seconds between 1900 and 1970
_NTP_PACKET_SIZE: int = 48
_NTP_CLIENT_BYTE0: int = 0x23            # LI=0, VN=4, Mode=3
_NTP_TRANSMIT_TS_OFFSET: int = 40
_NTP_STRATUM_OFFSET: int = 1

@dataclass
class NtpServerEntry:
    hostname: str
    port: int = 123
    nts_capable: bool = False
    timeout_ms: int = 2000
    max_rtt_ms: int = 500

    @staticmethod
    def default_pool() -> List["NtpServerEntry"]:
        return [
            NtpServerEntry("time.cloudflare.com", nts_capable=True,  timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.google.com",     nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.windows.com",    nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.apple.com",      nts_capable=False, timeout_ms=2000, max_rtt_ms=500),
            NtpServerEntry("time.nist.gov",       nts_capable=False, timeout_ms=3000, max_rtt_ms=800),
        ]

@dataclass
class NtpObservation:
    server_hostname: str
    unix_seconds: int
    rtt_ms: int
    stratum: int
    nts_authenticated: bool = False

@dataclass
class TimeObservation:
    """Aligned with SDK __init__.py and C++ TimeObservation struct."""
    server_hostname: str
    key_id: str
    unix_seconds: int
    signature_hex: str
    sequence: int

class NtpObservationFetcher:
    def __init__(
        self,
        hmac_key_hex: str,
        servers: Optional[List[NtpServerEntry]] = None,
        stratum_max: int = 3,
        max_workers: int = 10,
        key_id: str = "v1"
    ) -> None:
        if not hmac_key_hex:
            raise ValueError("hmac_key_hex must not be empty")

        # STAGE 4 FIX: Explicitly check for empty list to satisfy tests
        if servers is not None and len(servers) == 0:
            raise ValueError("server pool must not be empty")

        self._servers = servers if servers is not None else NtpServerEntry.default_pool()
        
        if not self._servers:
            raise ValueError("server pool must not be empty")

        self._hmac_key_hex = hmac_key_hex
        self._key_id = key_id
        self._stratum_max = stratum_max
        self._max_workers = max_workers

        self._seq_lock = threading.Lock()
        self._sequences: dict[str, int] = {s.hostname: 0 for s in self._servers}

    def fetch(self) -> List[TimeObservation]:
        observations: List[TimeObservation] = []
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {pool.submit(self._query_server, s): s for s in self._servers}
            for future in as_completed(futures):
                try:
                    raw = future.result()
                    if raw:
                        observations.append(self._sign_observation(raw))
                except Exception:
                    pass
        return observations

    def _query_server(self, server: NtpServerEntry) -> Optional[NtpObservation]:
        timeout_s = server.timeout_ms / 1000.0
        try:
            info = socket.getaddrinfo(server.hostname, server.port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            if not info: return None
            af, socktype, proto, _, addr = info[0]

            with socket.socket(af, socktype, proto) as sock:
                sock.settimeout(timeout_s)
                packet = bytearray(_NTP_PACKET_SIZE)
                packet[0] = _NTP_CLIENT_BYTE0

                t1 = time.monotonic()
                sock.sendto(bytes(packet), addr)
                response, _ = sock.recvfrom(_NTP_PACKET_SIZE)
                t4 = time.monotonic()

                if len(response) < _NTP_PACKET_SIZE: return None
                
                stratum = response[_NTP_STRATUM_OFFSET]
                if stratum == 0 or stratum > self._stratum_max: return None

                # Extract transmit timestamp
                ntp_seconds: int = struct.unpack_from("!I", response, _NTP_TRANSMIT_TS_OFFSET)[0]
                if ntp_seconds < _NTP_UNIX_OFFSET: return None

                server_unix = ntp_seconds - _NTP_UNIX_OFFSET
                rtt_ms = int((t4 - t1) * 1000)

                if rtt_ms > server.max_rtt_ms: return None

                return NtpObservation(
                    server_hostname=server.hostname,
                    unix_seconds=server_unix,
                    rtt_ms=rtt_ms,
                    stratum=stratum
                )
        except (socket.timeout, socket.gaierror, OSError):
            return None

    def _sign_observation(self, raw: NtpObservation) -> TimeObservation:
        with self._seq_lock:
            self._sequences[raw.server_hostname] = self._sequences.get(raw.server_hostname, 0) + 1
            seq = self._sequences[raw.server_hostname]

        # REPLAY PROTECTION: Match server-side string concatenation "host:ts:seq"
        payload = f"{raw.server_hostname}:{raw.unix_seconds}:{seq}"
        signature = hmac_sha256_hex(payload, self._hmac_key_hex)

        return TimeObservation(
            server_hostname=raw.server_hostname,
            key_id=self._key_id,
            unix_seconds=raw.unix_seconds,
            signature_hex=signature,
            sequence=seq
        )