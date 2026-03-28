"""
tests/test_auth.py

Unit tests for bridge/auth.py.
No C++ dependency.
"""

from __future__ import annotations

import time

import pytest

from bridge.auth import AuthContext, RateLimiter


class TestRateLimiter:
    def test_allows_under_limit(self):
        rl = RateLimiter(rps=100)
        for _ in range(10):
            assert rl.is_allowed("1.2.3.4")

    def test_blocks_over_limit(self):
        rl = RateLimiter(rps=5)
        results = [rl.is_allowed("10.0.0.1") for _ in range(20)]
        # First 5 should be allowed, rest denied
        assert all(results[:5])
        assert not all(results)

    def test_different_clients_independent(self):
        rl = RateLimiter(rps=2)
        # Exhaust client A
        rl.is_allowed("client-a")
        rl.is_allowed("client-a")
        # Client B should still be allowed
        assert rl.is_allowed("client-b")

    def test_refills_over_time(self):
        rl = RateLimiter(rps=10)
        # Exhaust tokens
        for _ in range(10):
            rl.is_allowed("x")
        assert not rl.is_allowed("x")
        # Wait for 2 tokens to refill
        time.sleep(0.25)
        assert rl.is_allowed("x")


class TestAuthContextInsecureDev:
    def test_bearer_check_always_passes(self, no_auth):
        assert no_auth.check_bearer(None)
        assert no_auth.check_bearer("")
        assert no_auth.check_bearer("Bearer wrong-token")

    def test_rate_check_always_passes(self, no_auth):
        for _ in range(10_000):
            assert no_auth.check_rate("1.1.1.1")


class TestAuthContextBearerRequired:
    def test_valid_token_passes(self, bearer_auth):
        assert bearer_auth.check_bearer("Bearer test-token-abc")

    def test_wrong_token_rejected(self, bearer_auth):
        assert not bearer_auth.check_bearer("Bearer wrong-token")

    def test_no_header_rejected(self, bearer_auth):
        assert not bearer_auth.check_bearer(None)

    def test_empty_header_rejected(self, bearer_auth):
        assert not bearer_auth.check_bearer("")

    def test_malformed_scheme_rejected(self, bearer_auth):
        assert not bearer_auth.check_bearer("Token test-token-abc")

    def test_requires_bearer_true(self, bearer_auth):
        assert bearer_auth.requires_bearer()


class TestAuthContextNoBearer:
    def test_requires_bearer_false_when_no_tokens(self, no_auth):
        assert not no_auth.requires_bearer()

    def test_any_bearer_accepted_when_not_configured(self):
        auth = AuthContext(bearer_tokens="", rate_limit_rps=100, insecure_dev=False)
        assert auth.check_bearer(None)
        assert auth.check_bearer("Bearer anything")


class TestAuthContextMultipleTokens:
    def test_multiple_tokens_all_valid(self):
        auth = AuthContext(bearer_tokens="token-a,token-b,token-c", rate_limit_rps=100, insecure_dev=False)
        assert auth.check_bearer("Bearer token-a")
        assert auth.check_bearer("Bearer token-b")
        assert auth.check_bearer("Bearer token-c")
        assert not auth.check_bearer("Bearer token-d")
