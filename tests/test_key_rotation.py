import pytest
import os
from uml001 import (
    ColdVault, ColdVaultConfig, OsStrongClock, 
    SimpleHashProvider, SimpleFileVaultBackend,
    KeyRotationManager, KeyRotationConfig
)

@pytest.fixture
def real_vault(tmp_path):
    """Provides a real ColdVault instance for KeyRotationManager tests."""
    base_dir = tmp_path / "vault_data"
    base_dir.mkdir()
    
    # ColdVault expects a directory, the backend handles the specific file
    log_file = base_dir / "vault.log"

    config = ColdVaultConfig()
    config.base_directory = str(base_dir)

    # We must keep these alive! If they are local variables that 
    # get garbage collected, the C++ side will segfault.
    clock = OsStrongClock()
    hash_provider = SimpleHashProvider()
    
    # Explicitly create the backend
    backend = SimpleFileVaultBackend(str(log_file))
    
    # Pass the backend as a shared_ptr. 
    # We attach these to the vault object in Python to prevent GC.
    vault = ColdVault(config, backend, clock, hash_provider)
    
    # Anchor the dependencies to the vault object so Python's GC 
    # doesn't reap them while the vault is still in use.
    # This requires py::dynamic_attr() in the C++ bindings!
    vault._backend_ref = backend
    vault._clock_ref = clock
    vault._hash_ref = hash_provider
    
    return vault

def test_key_rotation_triggers(real_vault):
    # 1. Setup Authorities
    authorities = {"time.cloudflare.com", "time.google.com"}

    # 2. Setup Config
    config = KeyRotationConfig()
    config.rotation_interval_seconds = 10
    config.overlap_window_seconds = 5

    # 3. Instantiate Manager
    mgr = KeyRotationManager(real_vault, authorities, config)

    # Initial state
    initial_version = mgr.key_version()

    # 4. Trigger rotation by passing a timestamp
    # This calls vault.log_key_rotation_event() internally
    mgr.maybe_rotate(100)

    # 5. Verify
    assert mgr.key_version() > initial_version
    
    # Verify the file was actually created and written to
    # Because of our binding fix, real_vault.config is now a property
    log_path = os.path.join(real_vault.config.base_directory, "vault.log")
    assert os.path.exists(log_path)