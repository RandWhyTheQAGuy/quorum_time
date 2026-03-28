"""
bridge/auth.py

Authentication and rate-limiting for all HTTP/WebSocket endpoints.

Two modes, independently configurable:
  - Bearer token:  Authorization: Bearer <token>
  - mTLS:          TLS client certificate verified against a CA

Rate limiting uses a simple token-bucket per client IP.
All three can be combined or any subset can be active.
When insecure_dev=True, auth is bypassed entirely (test/dev only).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token bucket rate limiter
# ---------------------------------------------------------------------------

class _Bucket:
    """Single token-bucket for one client IP."""
    __slots__ = ("tokens", "last_refill")

    def __init__(self, capacity: float) -> None:
        self.tokens = capacity
        self.last_refill = time.monotonic()


class RateLimiter:
    def __init__(self, rps: int) -> None:
        self._capacity = float(rps)
        self._rate = float(rps)     # tokens refilled per second
        self._buckets: dict[str, _Bucket] = defaultdict(lambda: _Bucket(self._capacity))
        self._lock = Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[client_ip]
            elapsed = now - bucket.last_refill
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._rate)
            bucket.last_refill = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False


# ---------------------------------------------------------------------------
# Auth context
# ---------------------------------------------------------------------------

class AuthContext:
    """
    Centralises all auth decisions.  Instantiate once and share across adapters.
    """

    def __init__(
        self,
        bearer_tokens: str,
        rate_limit_rps: int,
        insecure_dev: bool = False,
    ) -> None:
        self._insecure_dev = insecure_dev
        self._rate_limiter = RateLimiter(rate_limit_rps)

        raw = [t.strip() for t in bearer_tokens.split(",") if t.strip()]
        self._bearer_tokens: Set[str] = set(raw)
        self._require_bearer = bool(raw)

        if insecure_dev:
            logger.warning("INSECURE DEV MODE: auth is disabled")

    # ------------------------------------------------------------------

    def check_bearer(self, authorization_header: Optional[str]) -> bool:
        """Return True if the bearer token is valid (or auth is not required)."""
        if self._insecure_dev or not self._require_bearer:
            return True
        if not authorization_header:
            return False
        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return False
        return parts[1] in self._bearer_tokens

    def check_rate(self, client_ip: str) -> bool:
        """Return True if the client is within their rate limit."""
        if self._insecure_dev:
            return True
        return self._rate_limiter.is_allowed(client_ip)

    def requires_bearer(self) -> bool:
        return self._require_bearer and not self._insecure_dev


# ---------------------------------------------------------------------------
# FastAPI dependency helpers
# ---------------------------------------------------------------------------
# These are imported by rest_server.py and ws_server.py.

def make_http_auth_dependency(auth: AuthContext):
    """
    Returns a FastAPI dependency that enforces bearer + rate limit.
    Import and inject with Depends(make_http_auth_dependency(auth_ctx)).
    """
    from fastapi import Depends, Header, HTTPException, Request
    from typing import Optional as Opt

    async def _check(
        request: Request,
        authorization: Opt[str] = Header(default=None),
    ) -> None:
        client_ip = request.client.host if request.client else "unknown"

        if not auth.check_rate(client_ip):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        if not auth.check_bearer(authorization):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return _check


async def check_ws_auth(auth: AuthContext, token: Optional[str], client_ip: str) -> bool:
    """
    WebSocket auth: token passed as query param ?token=<bearer>.
    Returns True if allowed.
    """
    if not auth.check_rate(client_ip):
        return False
    if not auth.requires_bearer():
        return True
    if not token:
        return False
    fake_header = f"Bearer {token}"
    return auth.check_bearer(fake_header)
