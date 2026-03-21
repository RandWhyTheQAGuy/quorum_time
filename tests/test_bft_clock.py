import os
import pytest
import time

from uml001 import (
    OsStrongClock,
    SimpleHashProvider,
    SimpleFileVaultBackend,
    ColdVaultConfig,
    ColdVault,
    BftClockConfig,
    BFTQuorumTrustedClock,
    register_hmac_authority,
)

SECRET_KEY = "bft-clock-test-key"
KEY_ID     = "k"

# Your test suite should define this somewhere globally
AUTHORITIES = {"srv1", "srv2", "srv3"}


@pytest.fixture
def clock_setup(tmp_path):
    """
    Creates a fully initialized BFTQuorumTrustedClock + ColdVault instance
    consistent with the updated UML‑001 API.
    """

    # ------------------------------------------------------------
    # 1. Register authorities before constructing the clock
    # ------------------------------------------------------------
    secret_hex = SECRET_KEY.encode().hex()
    for host in AUTHORITIES:
        register_hmac_authority(host, KEY_ID, secret_hex)

    # ------------------------------------------------------------
    # 2. Construct vault components
    # ------------------------------------------------------------
    clock_os = OsStrongClock()
    hashp = SimpleHashProvider()

    cv_cfg = ColdVaultConfig()
    cv_cfg.base_directory = str(tmp_path)

    # The backend takes a *file path*, not a directory
    backend = SimpleFileVaultBackend(os.path.join(str(tmp_path), "vault.log"))

    vault = ColdVault(cv_cfg, backend, clock_os, hashp)

    # Anchor references to avoid GC (your pattern)
    vault._refs = [clock_os, hashp, backend]

    # ------------------------------------------------------------
    # 3. Configure BFT clock
    # ------------------------------------------------------------
    config = BftClockConfig()
    config.min_quorum = 3
    config.max_cluster_skew = 10
    config.max_drift_step = 5
    config.max_total_drift = 100
    config.fail_closed = False

    # ------------------------------------------------------------
    # 4. Construct the BFT clock
    # ------------------------------------------------------------
    clock = BFTQuorumTrustedClock(config, AUTHORITIES, vault)

    return clock, vault, config
