class ColdVaultMock:
    """
    Minimal Python implementation of ColdVault for pytest.
    Stores everything in memory.
    """

    def __init__(self):
        self.last_drift = None
        self.authority_sequences = {}
        self.security_events = []
        self.sync_events = []

    def load_last_drift(self):
        return self.last_drift

    def load_authority_sequences(self):
        return dict(self.authority_sequences)

    def save_authority_sequences(self, seq):
        self.authority_sequences = dict(seq)

    def log_sync_event(self, agreed_time, drift_step, total_drift):
        self.sync_events.append(
            (agreed_time, drift_step, total_drift)
        )

    def log_security_event(self, key, detail):
        self.security_events.append((key, detail))
