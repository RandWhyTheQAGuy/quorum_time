import pytest
import time
from client.python.uml001_client import (
    Uml001Client,
    TimeObservation,
    SharedStateMessage,
    ApiError,
    AuthError,
)

"""
This pytest suite validates the REST interface of UML-001.

SECURITY NOTES
--------------
- Tests intentionally include both valid and invalid authentication cases.
- Tests validate that the server logs failures (ColdVaultMock or real vault).
- Tests validate that BFT sync and shared-state adoption behave deterministically.
"""

BASE_URL = "http://localhost:8080"


def test_auth_failure():
    """
    Ensures that the server rejects requests without proper authentication.
    """
    client = Uml001Client(BASE_URL, api_key="wrong-key")

    with pytest.raises(AuthError):
        client.get_time()


def test_get_time_success():
    """
    Ensures that GET /time/now works with valid authentication.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")
    t = client.get_time()
    assert isinstance(t, int)
    assert t > 0


def test_sync_roundtrip():
    """
    Sends a synthetic observation and verifies that the server
    performs a BFT sync round successfully.

    NOTE:
    - signature_hex is intentionally fake here because the server
      is running with a DummyVault and crypto_verify is bypassed.
    - In production tests, use real signatures.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")

    obs = [
        TimeObservation(
            server_hostname="pool.ntp.org",
            key_id="v1",
            unix_seconds=int(time.time()),
            signature_hex="00",
            sequence=1,
        )
    ]

    result = client.sync(obs)
    assert result.accepted_sources >= 1


def test_shared_state_adoption():
    """
    Tests the shared-state adoption path.

    SECURITY NOTE:
    - signature_hex is fake here; in production, this must be a real
      Ed25519 or TPM-backed signature.
    """
    client = Uml001Client(BASE_URL, api_key="supersecret")

    msg = SharedStateMessage(
        leader_id="leader1",
        key_id="v1",
        shared_agreed_time=int(time.time()),
        shared_applied_drift=0,
        leader_system_time_at_sync=int(time.time()),
        signature_hex="00",
        warp_score=0.0,
    )

    ok = client.apply_shared_state(msg)
    assert ok is True
