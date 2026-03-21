import tempfile
import os
import shutil
import uml001
from typing import Dict, List, Optional

class MockVault:
    """
    In-memory vault suitable for pytest fixtures and local development.
    """

    def __init__(self, initial_drift: int = 0, tmp_dir: Optional[str] = None):
        # Cold-start state
        self.drift: int = initial_drift
        self.sequences: Dict[str, int] = {}

        # Audit capture
        self.security_events: List[dict] = []
        self.sync_events: List[dict] = []
        self.log: List[str] = []

        # Filesystem backend setup
        self._owns_tmp = tmp_dir is None
        self._tmp_dir = tmp_dir or tempfile.mkdtemp(prefix="mock_vault_")
        
        # Ensure directory exists if passed from outside
        os.makedirs(self._tmp_dir, exist_ok=True)

        # Fix: SimpleFileVaultBackend needs a FILE path, not a DIR path
        self.audit_file = os.path.join(self._tmp_dir, "audit.log")
        self.backend = uml001.SimpleFileVaultBackend(self.audit_file)

    def __del__(self):
        if hasattr(self, '_owns_tmp') and self._owns_tmp and os.path.isdir(self._tmp_dir):
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def log_security_event(self, key: str, detail: str) -> None:
        entry = {"key": key, "detail": detail}
        self.security_events.append(entry)

        line = f"security_event key={key} detail={detail}"
        self.log.append(line)
        # Assuming C++ method is log_event per IVaultBackend interface
        self.backend.log_event(line) 

    def log_sync_event(self, agreed_time: int, step: int, total_drift: int) -> None:
        entry = {
            "agreed_time": agreed_time,
            "step":        step,
            "total_drift": total_drift,
        }
        self.sync_events.append(entry)

        line = (
            f"bft.sync.committed agreed_time={agreed_time} "
            f"step={step} total_drift={total_drift}"
        )
        self.log.append(line)
        self.backend.log_event(line)

    def log_key_rotation_event(self, key_version: int, unix_time: int) -> None:
        line = f"key_rotation version={key_version} unix_time={unix_time}"
        self.log.append(line)
        self.backend.log_event(line)

    def save_last_drift(self, drift: int) -> None:
        self.drift = drift

    def load_last_drift(self) -> int:
        return self.drift if self.drift is not None else 0

    def save_authority_sequences(self, sequences: Dict[str, int]) -> None:
        self.sequences = dict(sequences)

    def load_authority_sequences(self) -> Dict[str, int]:
        return dict(self.sequences)

    def read_all(self) -> List[str]:
        return list(self.log)

    def clear(self) -> None:
        self.security_events.clear()
        self.sync_events.clear()
        self.log.clear()
        self.drift = 0
        self.sequences.clear()