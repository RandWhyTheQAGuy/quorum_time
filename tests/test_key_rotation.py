import uml001


class DummyVault:
    def __init__(self):
        self.events = []

    def log_key_rotation_event(self, version, ts):
        self.events.append((version, ts))


def test_key_rotation_triggers():
    vault = DummyVault()
    authorities = {"a", "b"}

    mgr = uml001.KeyRotationManager(
        vault,
        authorities,
        10,   # rotation interval
        5,    # overlap
        True  # use_hmac
    )

    mgr.maybe_rotate(100)
    assert vault.events  # rotation logged
