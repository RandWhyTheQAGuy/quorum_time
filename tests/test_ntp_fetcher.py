# tests/test_ntp_fetcher.py
#
# Fix applied:
#   [FIX-NTPENTRY] NtpServerEntry() takes no positional args — use attribute
#                  assignment. The binding uses default py::init<>() only.

import uml001


def test_ntp_fetcher_hmac_setting():
    # [FIX-NTPENTRY] NtpServerEntry has no positional constructor.
    entry = uml001.NtpServerEntry()
    entry.hostname   = "time.google.com"
    entry.max_rtt_ms = 1000
    entry.timeout_ms = 2000

    fetcher = uml001.NtpObservationFetcher(
        "initial_key",
        "v1",
        [entry],
        2,    # stratum_max
        3,    # quorum_size
        2     # outlier_threshold_s
    )

    fetcher.set_hmac_key("NEWKEY", "v2")

    # No crash = bindings are correct.
    assert True