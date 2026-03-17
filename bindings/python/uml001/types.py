from dataclasses import dataclass
from typing import List

@dataclass
class TimeObservation:
    server_hostname: str
    key_id: str
    unix_seconds: int
    signature_hex: str
    sequence: int

@dataclass
class TimestampAttestationToken:
    unix_time: int
    median_rtt: int
    drift_ppm: int
    quorum_servers: List[str]
    quorum_hash: str
    signature: str
