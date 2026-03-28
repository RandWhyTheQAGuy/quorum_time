"""
bridge/ntp_udp_server.py

Minimal NTPv4 UDP server (RFC 5905).

Listens on UDP port 1123 by default (or 123 when running as root / with
CAP_NET_BIND_SERVICE).  Responds to NTP client requests using the agreed
BFT quorum time.

This server:
  - Sets LI=0, VN=4, Mode=4 (server), Stratum=1
  - Copies the client's Transmit Timestamp into the Originate Timestamp
    field of the response (required by RFC 5905 §9)
  - Sets Reference, Receive, and Transmit Timestamps to the BFT agreed time
  - Sets Root Dispersion from the current uncertainty window

Limitations (intentional for v1):
  - No authentication extension (NTS / MAC) - add as a follow-on
  - No Kiss-o'-Death handling
  - Single-threaded request loop (sufficient for sidecar use)
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Optional

from .clock_state import ClockState
from .formats import to_ntp_packet

logger = logging.getLogger(__name__)

_NTP_PACKET_SIZE = 48
_NTP_DELTA = 2_208_988_800   # seconds between 1900 and 1970 epochs


def _patch_originate(response: bytes, client_packet: bytes) -> bytes:
    """
    RFC 5905 §9: the server MUST copy the client's Transmit Timestamp
    into the Originate Timestamp field of the response.

    NTP packet layout (all big-endian):
      Offset  Field                 Size
      0       LI/VN/Mode + flags    4 bytes
      16      Reference Timestamp   8 bytes
      24      Originate Timestamp   8 bytes  <-- overwrite here
      32      Receive Timestamp     8 bytes
      40      Transmit Timestamp    8 bytes
    """
    if len(client_packet) < 48:
        return response

    # Client transmit timestamp is at bytes 40-47
    client_tx = client_packet[40:48]
    patched = bytearray(response)
    patched[24:32] = client_tx
    return bytes(patched)


class NtpUdpServer:
    def __init__(self, state: ClockState, port: int = 1123) -> None:
        self._state = state
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(1.0)
        self._sock.bind(("0.0.0.0", self._port))
        self._thread = threading.Thread(
            target=self._run,
            name="aegis-ntp-udp",
            daemon=True,
        )
        self._thread.start()
        logger.info("NTP UDP server listening on :%d", self._port)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                self._handle(data, addr)
            except Exception:
                logger.exception("NTP request handling error for %s", addr)

    def _handle(self, data: bytes, addr: tuple) -> None:
        assert self._sock is not None

        # Ignore malformed packets
        if len(data) < 48:
            return

        # Check it is a client request (Mode=3) or symmetric (Mode=1/2)
        mode = data[0] & 0x07
        if mode not in (1, 2, 3):
            return

        try:
            at = self._state.get_or_raise()
        except RuntimeError:
            # Not yet initialised - send Kiss-o'-Death DENY
            logger.warning("NTP request received but clock not ready - dropping")
            return

        response = to_ntp_packet(at)
        response = _patch_originate(response, data)

        try:
            self._sock.sendto(response, addr)
        except OSError as exc:
            logger.warning("NTP sendto %s failed: %s", addr, exc)
