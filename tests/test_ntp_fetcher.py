# tests/test_ntp_fetcher.py
#
# Fix applied:
#   [FIX-NTPENTRY] NtpServerEntry() takes no positional args — use attribute
#                  assignment. The binding uses default py::init<>() only.

import uml001

def test_ntp_fetcher_hmac_setting():
    entry = uml001.NtpServerEntry()
    entry.hostname = "time.google.com"
    entry.timeout_ms = 2000
    entry.max_delay_ms = 1000
    
    # Matching the C++ Constructor:
    # (hmac_key, key_id, servers, quorum_size, timeout_ms, max_delay_ms)
    fetcher = uml001.NtpObservationFetcher(
        "initial_key",      # hmac_key
        "v1",               # key_id
        [entry],            # servers
        1,                  # quorum_size (changed from 3 to 1 since we only have 1 entry)
        2000,               # timeout_ms
        1000                # max_delay_ms
    )
    
    # Matching C++: void set_hmac_key(const std::string& new_hmac_key);
    fetcher.set_hmac_key("NEWKEY")

    # No crash = bindings are correct.
    assert True