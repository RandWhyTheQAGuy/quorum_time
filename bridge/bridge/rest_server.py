"""
bridge/rest_server.py

FastAPI REST adapter.

Endpoints
---------
GET /v1/time                 JSON envelope (full attestation, default)
GET /v1/time?format=unix     Unix epoch + nanos
GET /v1/time?format=iso8601  RFC 3339 timestamp
GET /v1/time?format=json     Full attestation envelope (same as default)
GET /healthz                 Liveness probe (no auth required)
GET /readyz                  Readiness probe (no auth required)
GET /metrics                 Prometheus-compatible text metrics (no auth required)
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from .auth import AuthContext, make_http_auth_dependency
from .clock_state import ClockState
from .formats import SUPPORTED_FORMATS, format_response

logger = logging.getLogger(__name__)


def build_app(state: ClockState, auth: AuthContext) -> FastAPI:
    app = FastAPI(
        title="Aegis Bridge",
        description="BFT quorum trusted clock consumer bridge",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    auth_dep = make_http_auth_dependency(auth)

    # ------------------------------------------------------------------ /v1/time

    @app.get("/v1/time", dependencies=[Depends(auth_dep)])
    async def get_time(
        format: Optional[str] = Query(
            default="json",
            description=f"Response format. One of: {', '.join(SUPPORTED_FORMATS)}",
        ),
    ) -> JSONResponse:
        try:
            at = state.get_or_raise()
        except RuntimeError as exc:
            return JSONResponse(status_code=503, content={"error": str(exc)})

        try:
            body = format_response(at, format or "json")
        except ValueError as exc:
            return JSONResponse(status_code=400, content={"error": str(exc)})

        return JSONResponse(content=body)

    # ------------------------------------------------------------------ /healthz

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        """
        Liveness probe.  Always returns 200 if the process is running.
        The readiness probe (/readyz) is the correct check for traffic routing.
        """
        return PlainTextResponse("ok")

    # ------------------------------------------------------------------ /readyz

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> Response:
        """
        Readiness probe.  Returns 200 only when the clock has a fresh quorum
        result and is within the staleness window.
        """
        if state.is_healthy():
            return PlainTextResponse("ok")
        at = state.get()
        if at is None:
            detail = "clock not yet initialised"
        else:
            detail = f"clock data stale ({state.age_seconds():.1f}s old)"
        return PlainTextResponse(detail, status_code=503)

    # ------------------------------------------------------------------ /metrics

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        """
        Prometheus-compatible text format (no auth - scraped internally).
        """
        at = state.get()
        healthy = 1 if state.is_healthy() else 0
        age = state.age_seconds()
        errors = state.error_count()

        lines = [
            "# HELP aegis_bridge_healthy 1 if the clock has a fresh quorum result",
            "# TYPE aegis_bridge_healthy gauge",
            f"aegis_bridge_healthy {healthy}",
            "",
            "# HELP aegis_bridge_clock_age_seconds Seconds since last successful quorum sync",
            "# TYPE aegis_bridge_clock_age_seconds gauge",
            f"aegis_bridge_clock_age_seconds {age:.3f}",
            "",
            "# HELP aegis_bridge_poll_errors_total Total number of failed poll ticks",
            "# TYPE aegis_bridge_poll_errors_total counter",
            f"aegis_bridge_poll_errors_total {errors}",
        ]

        if at is not None:
            lines += [
                "",
                "# HELP aegis_bridge_uncertainty_ms Current quorum uncertainty window (ms)",
                "# TYPE aegis_bridge_uncertainty_ms gauge",
                f"aegis_bridge_uncertainty_ms {at.uncertainty_ms:.3f}",
                "",
                "# HELP aegis_bridge_drift_ppm Current clock drift estimate (ppm)",
                "# TYPE aegis_bridge_drift_ppm gauge",
                f"aegis_bridge_drift_ppm {at.drift_ppm:.6f}",
                "",
                "# HELP aegis_bridge_accepted_sources Number of accepted NTP sources in last quorum",
                "# TYPE aegis_bridge_accepted_sources gauge",
                f"aegis_bridge_accepted_sources {len(at.accepted_sources)}",
            ]

        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")

    return app
