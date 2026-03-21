# tests/test_vault.py
import pytest
import os
import uml001
from pathlib import Path

@pytest.fixture
def vault_setup(tmp_path):
    tmp_dir = str(tmp_path)
    
    # 1. Create components
    clock = uml001.OsStrongClock()
    hashp = uml001.SimpleHashProvider()
    log_file = os.path.join(tmp_dir, "vault.log")
    backend = uml001.SimpleFileVaultBackend(log_file)

    # 2. Configure
    cfg = uml001.ColdVaultConfig()
    cfg.base_directory = tmp_dir 

    # 3. Instantiate
    vault = uml001.ColdVault(cfg, backend, clock, hashp)
    
    # 🛡️ ANCHOR REFERENCES (Prevents Segfault)
    vault._clock_ref = clock
    vault._hash_ref = hashp
    vault._backend_ref = backend
    
    return vault, tmp_dir