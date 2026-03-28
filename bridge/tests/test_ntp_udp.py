"""
tests/test_ntp_udp.py

Unit tests for bridge/ntp_udp_server.py.
Tests packet construction and originate-timestamp patching logic.
No C++ dependency.
"""

from __future__ import annotations

import struct
import time

import pytest

from bridge.formats import to_ntp_packet
from bridge.ntp_udp_server import NtpUdpServer, _patch_originate
from tests.conftest import make_attested_time

_NTP_DELTA = 2_208_988_800


def _make_client_packet(tx_sec: int = 99999999, tx_frac: int = 12345) -> bytes:
    """Build a minimal 48-byte NTPv4 client request (Mode=3)."""
    flags = (0 << 6) | (4 << 3) | 3   # LI=0, VN=4, Mode=3 (client)
    # Fields: flags, stratum, poll, precision, root_delay, root_dispersion,
    # ref_id, ref_ts(2), orig_ts(2), rx_ts(2), tx_ts(2)
    return struct.pack(
        "!B B b b I I I II II II II",
        flags, 0, 0, 0,
        0, 0, 0,
        0, 0,   # reference ts
        0, 0,   # originate ts
        0, 0,   # receive ts
        tx_sec, tx_frac,  # transmit ts
    )


class TestPatchOriginate:
    def test_client_tx_copied_to_originate(self):
        at = make_attested_time()
        response = to_ntp_packet(at)
        tx_sec = 88888888
        tx_frac = 55555
        client_pkt = _make_client_packet(tx_sec, tx_frac)

        patched = _patch_originate(response, client_pkt)

        # Originate timestamp is at bytes 24-31
        orig_sec, orig_frac = struct.unpack("!II", patched[24:32])
        assert orig_sec == tx_sec
        assert orig_frac == tx_frac

    def test_transmit_timestamp_unchanged(self):
        at = make_attested_time(unix_seconds=1_700_000_000.0)
        response = to_ntp_packet(at)
        client_pkt = _make_client_packet()
        patched = _patch_originate(response, client_pkt)

        tx_sec_before = struct.unpack("!I", response[40:44])[0]
        tx_sec_after = struct.unpack("!I", patched[40:44])[0]
        assert tx_sec_before == tx_sec_after

    def test_short_client_packet_returns_response_unchanged(self):
        at = make_attested_time()
        response = to_ntp_packet(at)
        patched = _patch_originate(response, b"\x00" * 10)
        assert patched == response

    def test_response_length_preserved(self):
        at = make_attested_time()
        response = to_ntp_packet(at)
        client_pkt = _make_client_packet()
        patched = _patch_originate(response, client_pkt)
        assert len(patched) == 48


class TestNtpUdpServerLifecycle:
    def test_start_stop(self, populated_state):
        server = NtpUdpServer(populated_state, port=11230)
        server.start()
        time.sleep(0.05)
        server.stop(timeout=2.0)

    def test_port_in_use_raises(self, populated_state):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 11231))
        try:
            server = NtpUdpServer(populated_state, port=11231)
            with pytest.raises(OSError):
                server.start()
        finally:
            sock.close()

    def test_responds_to_client_request(self, populated_state):
        import socket
        server = NtpUdpServer(populated_state, port=11232)
        server.start()
        time.sleep(0.05)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(1.0)
            client_pkt = _make_client_packet(tx_sec=123456789, tx_frac=0)
            client.sendto(client_pkt, ("127.0.0.1", 11232))
            data, _ = client.recvfrom(512)
            client.close()

            assert len(data) == 48
            # Check Mode=4 (server) in response
            assert (data[0] & 0x07) == 4
            # Check Stratum=1
            assert data[1] == 1
            # Check originate timestamp was patched
            orig_sec = struct.unpack("!I", data[24:28])[0]
            assert orig_sec == 123456789
        finally:
            server.stop()

    def test_drops_request_when_clock_empty(self, empty_state):
        import socket
        server = NtpUdpServer(empty_state, port=11233)
        server.start()
        time.sleep(0.05)

        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(0.3)
            client_pkt = _make_client_packet()
            client.sendto(client_pkt, ("127.0.0.1", 11233))
            with pytest.raises(socket.timeout):
                client.recvfrom(512)
            client.close()
        finally:
            server.stop()
