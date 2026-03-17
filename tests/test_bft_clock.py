import uml001


class DeterministicClock(uml001.IStrongClock):
    def __init__(self):
        self.t = 1_000_000

    def now_unix(self):
        return self.t

    def get_current_drift(self):
        return 0

    def advance(self, seconds):
        self.t += seconds


class DeterministicHash(uml001.IHashProvider):
    def sha256(self, s: str) -> str:
        return "HASH(" + s + ")"


def make_vault(tmp):
    backend = uml001.FileVaultBackend(tmp)
    clock = DeterministicClock()
    hashp = DeterministicHash()
    return uml001.ColdVault(
        uml001.ColdVault.Config(tmp),
        backend,
        clock,
        hashp
    ), backend, clock


def test_bft_rejects_unknown_authority(tmp_path):
    vault, backend, clock = make_vault(str(tmp_path))

    cfg = uml001.BftClockConfig()
    authorities = {"srv1", "srv2"}

    bft = uml001.BFTQuorumTrustedClock(cfg, authorities, vault)

    obs = uml001.TimeObservation("evil.com", "k", 1000, 1, "sig")

    assert bft.verify_observation(obs) is False
    assert any("unknown_authority" in line for line in backend.read_all())


def test_bft_accepts_valid_quorum(tmp_path):
    vault, backend, clock = make_vault(str(tmp_path))

    cfg = uml001.BftClockConfig(
        min_quorum=3,
        max_cluster_skew=10,
        max_drift_step=5,
        max_total_drift=100,
        fail_closed=False
    )

    authorities = {"srv1", "srv2", "srv3"}

    bft = uml001.BFTQuorumTrustedClock(cfg, authorities, vault)

    obs = [
        uml001.TimeObservation("srv1", "k", 1000, 1, "sig"),
        uml001.TimeObservation("srv2", "k", 1001, 2, "sig"),
        uml001.TimeObservation("srv3", "k", 1002, 3, "sig"),
    ]

    result = bft.update_and_sync(obs)
    assert result is not None
    assert any("sync.committed" in line for line in backend.read_all())
