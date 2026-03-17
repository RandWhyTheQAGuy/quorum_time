import uml001


def test_ntp_fetcher_hmac_setting():
    servers = [
        uml001.NtpServerEntry("time.google.com", 1000, 2000)
    ]

    fetcher = uml001.NtpObservationFetcher(
        "initial_key",
        "v1",
        servers,
        2,
        3,
        2
    )

    fetcher.set_hmac_key("NEWKEY", "v2")

    # No crash = success; bindings are correct
    assert True
