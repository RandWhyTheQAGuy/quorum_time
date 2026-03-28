"""
tests/test_formats.py

Unit tests for bridge/formats.py.
No C++ dependency.
"""

from __future__ import annotations

import struct
import time

import pytest

from bridge.formats import (
    AttestedTime,
    SUPPORTED_FORMATS,
    format_response,
    to_iso8601,
    to_json_envelope,
    to_ntp_packet,
    to_unix,
)
from tests.conftest import make_attested_time


class TestToUnix:
    def test_whole_seconds(self):
        at = make_attested_time(unix_seconds=1_700_000_000.0)
        result = to_unix(at)
        assert result["unix_seconds"] == 1_700_000_000
        assert result["unix_nanos"] == 0
        assert "uncertainty_ms" in result

    def test_fractional_seconds(self):
        at = make_attested_time(unix_seconds=1_700_000_000.5)
        result = to_unix(at)
        assert result["unix_seconds"] == 1_700_000_000
        # 0.5s = 500_000_000 ns
        assert abs(result["unix_nanos"] - 500_000_000) < 1000

    def test_uncertainty_present(self):
        at = make_attested_time(uncertainty_ms=12.5)
        result = to_unix(at)
        assert result["uncertainty_ms"] == pytest.approx(12.5)


class TestToIso8601:
    def test_utc_suffix(self):
        at = make_attested_time()
        result = to_iso8601(at)
        assert result["timestamp"].endswith("Z")

    def test_format_structure(self):
        at = make_attested_time(unix_seconds=1_700_000_000.0)
        result = to_iso8601(at)
        ts = result["timestamp"]
        # Should be parseable as RFC 3339
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt.tzinfo is not None

    def test_fields_present(self):
        at = make_attested_time(drift_ppm=0.5, quorum_hash_hex="abc123")
        result = to_iso8601(at)
        assert "timestamp" in result
        assert "uncertainty_ms" in result
        assert "drift_ppm" in result
        assert "quorum_hash" in result
        assert result["quorum_hash"] == "abc123"


class TestToJsonEnvelope:
    def test_all_fields_present(self):
        at = make_attested_time(
            accepted_sources=["a.example.com", "b.example.com"],
            rejected_sources=["c.example.com"],
        )
        result = to_json_envelope(at)
        assert "unix_seconds" in result
        assert "unix_nanos" in result
        assert "iso8601" in result
        assert "uncertainty_ms" in result
        assert "drift_ppm" in result
        assert "quorum" in result
        assert result["quorum"]["accepted_sources"] == ["a.example.com", "b.example.com"]
        assert result["quorum"]["rejected_sources"] == ["c.example.com"]
        assert "quorum_hash" in result["quorum"]

    def test_unix_seconds_consistent(self):
        at = make_attested_time(unix_seconds=1_700_000_000.123)
        result = to_json_envelope(at)
        assert result["unix_seconds"] == 1_700_000_000


class TestToNtpPacket:
    def test_packet_length(self):
        at = make_attested_time()
        pkt = to_ntp_packet(at)
        assert len(pkt) == 48

    def test_flags_byte(self):
        at = make_attested_time()
        pkt = to_ntp_packet(at)
        # LI=0, VN=4, Mode=4 -> 0b00_100_100 = 0x24
        assert pkt[0] == 0x24

    def test_stratum(self):
        at = make_attested_time()
        pkt = to_ntp_packet(at)
        assert pkt[1] == 1  # stratum 1

    def test_transmit_timestamp_nonzero(self):
        at = make_attested_time(unix_seconds=1_700_000_000.0)
        pkt = to_ntp_packet(at)
        # Transmit timestamp is at bytes 40-47 (NTP seconds at 40-43)
        ntp_sec = struct.unpack("!I", pkt[40:44])[0]
        assert ntp_sec > 0

    def test_ntp_epoch_offset(self):
        at = make_attested_time(unix_seconds=0.0)
        pkt = to_ntp_packet(at)
        ntp_sec = struct.unpack("!I", pkt[40:44])[0]
        # Unix 0 = NTP 2208988800
        assert ntp_sec == 2_208_988_800


class TestFormatDispatch:
    def test_unix_dispatch(self):
        at = make_attested_time()
        result = format_response(at, "unix")
        assert "unix_seconds" in result

    def test_iso8601_dispatch(self):
        at = make_attested_time()
        result = format_response(at, "iso8601")
        assert "timestamp" in result

    def test_json_dispatch(self):
        at = make_attested_time()
        result = format_response(at, "json")
        assert "quorum" in result

    def test_rfc3339_alias(self):
        at = make_attested_time()
        result = format_response(at, "rfc3339")
        assert "timestamp" in result

    def test_case_insensitive(self):
        at = make_attested_time()
        assert format_response(at, "ISO8601") == format_response(at, "iso8601")

    def test_unknown_format_raises(self):
        at = make_attested_time()
        with pytest.raises(ValueError, match="Unknown format"):
            format_response(at, "xml")

    def test_supported_formats_constant(self):
        assert "unix" in SUPPORTED_FORMATS
        assert "iso8601" in SUPPORTED_FORMATS
        assert "json" in SUPPORTED_FORMATS
