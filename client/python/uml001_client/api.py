import requests
from typing import List, Optional

from .models import (
    TimeObservation,
    BftSyncResult,
    SharedStateMessage,
)
from .exceptions import ApiError, AuthError, ServerError


class Uml001Client:
    """
    Python client SDK for the UML-001 Trusted Time REST API.

    SECURITY NOTES
    --------------
    - If API_KEY auth is enabled on the server, pass api_key="..." to the client.
    - If MTLS is enabled, configure:
        cert=("client.crt", "client.key")
        verify="ca.crt"
    - All server errors and auth failures raise typed exceptions.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        cert: Optional[tuple] = None,
        verify: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.cert = cert
        self.verify = verify
        self.timeout = timeout

    # -----------------------------
    # Internal request helper
    # -----------------------------
    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{path}"

        headers = kwargs.pop("headers", {})
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                cert=self.cert,
                verify=self.verify,
                timeout=self.timeout,
                **kwargs,
            )
        except Exception as e:
            raise ApiError(f"Request failed: {e}")

        if resp.status_code == 401:
            raise AuthError("Unauthorized")

        if resp.status_code >= 500:
            raise ServerError(f"Server error {resp.status_code}: {resp.text}")

        return resp

    # -----------------------------
    # GET /time/now
    # -----------------------------
    def get_time(self) -> int:
        resp = self._request("GET", "/time/now")
        data = resp.json()
        return data["unix_time"]

    # -----------------------------
    # POST /time/sync
    # -----------------------------
    def sync(self, observations: List[TimeObservation], warp_score: float = 0.0) -> BftSyncResult:
        payload = {
            "warp_score": warp_score,
            "observations": [o.__dict__ for o in observations],
        }

        resp = self._request("POST", "/time/sync", json=payload)

        if resp.status_code == 409:
            raise ApiError("Sync failed: quorum or drift ceiling exceeded")

        data = resp.json()
        return BftSyncResult(**data)

    # -----------------------------
    # POST /time/shared-state
    # -----------------------------
    def apply_shared_state(self, msg: SharedStateMessage) -> bool:
        resp = self._request("POST", "/time/shared-state", json=msg.__dict__)

        if resp.status_code == 409:
            raise ApiError("Shared state rejected")

        return True
