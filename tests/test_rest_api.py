# tests/test_rest_api.py
#
# REST API tests for UML-001.
# Assumes a running server at BASE_URL with matching API key config.

import time
import pytest

from client.python.uml001_client import (
    Uml001Client,
    TimeObservation,
    SharedStateMessage,
    ApiError,
    AuthError,
)


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
      is expected to run with a DummyVault or bypassed crypto_verify
      in this test environment.
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
