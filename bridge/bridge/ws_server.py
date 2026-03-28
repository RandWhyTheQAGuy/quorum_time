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
