import requests
from typing import List, Optional
from .models import TimeObservation, BftSyncResult, SharedStateMessage
from .exceptions import ApiError, AuthError, ServerError

class Uml001Client:
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

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{path}"
        headers = kwargs.pop("headers", {})
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            resp = requests.request(
                method, url, headers=headers, cert=self.cert,
                verify=self.verify, timeout=self.timeout, **kwargs,
            )
        except Exception as e:
            raise ApiError(f"Connection failed: {e}")

        if resp.status_code == 401:
            raise AuthError(f"Unauthorized: {resp.text}")
        if resp.status_code >= 500:
            raise ServerError(f"Server error {resp.status_code}: {resp.text}")

        return resp

    def get_time(self) -> int:
        resp = self._request("GET", "/time/now")
        data = resp.json()
        # Aegis servers often use 'unix_seconds' or 'unix_time'
        return data.get("unix_time") or data.get("unix_seconds", 0)

    def sync(self, observations: List[TimeObservation], warp_score: float = 0.0) -> BftSyncResult:
        # Using __dict__ works for simple dataclasses
        payload = {
            "warp_score": warp_score,
            "observations": [o.__dict__ for o in observations],
        }
        resp = self._request("POST", "/time/sync", json=payload)
        
        if resp.status_code == 409:
            raise ApiError("Sync rejected: Drift or Quorum failure")
            
        return BftSyncResult(**resp.json())

    def apply_shared_state(self, msg: SharedStateMessage) -> bool:
        resp = self._request("POST", "/time/shared-state", json=msg.__dict__)
        if resp.status_code != 200:
            return False
        return True