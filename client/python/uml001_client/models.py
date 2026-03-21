from dataclasses import dataclass, asdict

@dataclass
class TimeObservation:
    server_hostname: str
    key_id: str
    unix_seconds: int
    signature_hex: str
    sequence: int

@dataclass
class BftSyncResult:
    agreed_time: int
    applied_drift: int
    accepted_sources: int
    outliers_ejected: int
    rejected_sources: int

@dataclass
class SharedStateMessage:
    leader_id: str
    key_id: str
    shared_agreed_time: int
    shared_applied_drift: int
    leader_system_time_at_sync: int
    signature_hex: str
    warp_score: float = 0.0