# Quorum Time — Open Trusted Time & Distributed Verification Framework
# Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
# SPDX-License-Identifier: Apache-2.0
#
# Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
# system designed for modern distributed environments. It provides a
# cryptographically anchored notion of time that can be aligned,
# audited, and shared across domains without requiring centralized
# trust.
#
# This project also includes the Aegis Semantic Passport components,
# which complement Quorum Time by offering structured, verifiable
# identity and capability attestations for agents and services.
#
# Core capabilities:
#   - BFT Quorum Time: multi-authority, tamper-evident time agreement
#                      with drift bounds, authority attestation, and
#                      cross-domain alignment (AlignTime).
#
#   - Transparency Logging: append-only, hash-chained audit records
#                           for time events, alignment proofs, and
#                           key-rotation operations.
#
#   - Open Integration: designed for interoperability with distributed
#                       systems, security-critical infrastructure,
#                       autonomous agents, and research environments.
#
# Quorum Time is developed as an open-source project with a focus on
# clarity, auditability, and long-term maintainability. Contributions,
# issue reports, and discussions are welcome.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This implementation is intended for open research, practical
# deployment, and community-driven evolution of verifiable time and
# distributed trust standards.
#
"""
bridge/ws_server.py

WebSocket push adapter.

Endpoint
--------
ws://<host>:8081/v1/stream?format=json&token=<bearer>

On connect, immediately sends the current AttestedTime snapshot.
Subsequently pushes a new message on every ClockState update (i.e. every
poll tick) OR at ws_push_interval_seconds cadence, whichever fires first.

The connection is closed with code 4401 on auth failure and 4429 on
rate-limit violation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect

from .auth import AuthContext, check_ws_auth
from .clock_state import ClockState
from .formats import SUPPORTED_FORMATS, format_response

logger = logging.getLogger(__name__)


def build_ws_app(state: ClockState, auth: AuthContext, push_interval: float) -> FastAPI:
    app = FastAPI(title="Aegis Bridge WebSocket", docs_url=None, redoc_url=None)

    @app.websocket("/v1/stream")
    async def ws_stream(
        websocket: WebSocket,
        format: Optional[str] = Query(default="json"),
        token: Optional[str] = Query(default=None),
    ) -> None:
        client_ip = websocket.client.host if websocket.client else "unknown"

        allowed = await check_ws_auth(auth, token, client_ip)
        if not allowed:
            await websocket.close(code=4401)
            return

        await websocket.accept()
        logger.info("WebSocket client connected: %s fmt=%s", client_ip, format)

        fmt = (format or "json").lower()
        if fmt not in SUPPORTED_FORMATS:
            await websocket.send_text(
                json.dumps({"error": f"Unknown format '{fmt}'. Valid: {', '.join(SUPPORTED_FORMATS)}"})
            )
            await websocket.close(code=1008)
            return

        try:
            # Send immediately on connect
            at = state.get()
            if at is not None:
                await websocket.send_text(json.dumps(format_response(at, fmt)))

            loop = asyncio.get_event_loop()

            while True:
                # Wait for a state update or push interval, whichever fires first.
                # state.wait_for_update is blocking - run in executor to avoid blocking event loop.
                got_update = await loop.run_in_executor(
                    None, state.wait_for_update, push_interval
                )

                at = state.get()
                if at is None:
                    await asyncio.sleep(0.1)
                    continue

                try:
                    msg = json.dumps(format_response(at, fmt))
                    await websocket.send_text(msg)
                except RuntimeError as exc:
                    await websocket.send_text(json.dumps({"error": str(exc)}))

        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected: %s", client_ip)
        except Exception:
            logger.exception("WebSocket error for client %s", client_ip)
            try:
                await websocket.close(code=1011)
            except Exception:
                pass

    return app
