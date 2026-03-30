#!/usr/bin/env bash
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
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
SERVER_BIN="$BUILD_DIR/uml001_rest_server"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
BASE_URL="http://$HOST:$PORT"
API_KEY="${API_KEY:-supersecret}"

if [[ ! -x "$SERVER_BIN" ]]; then
  echo "missing $SERVER_BIN"
  echo "build with: cmake -S \"$ROOT_DIR\" -B \"$BUILD_DIR\" -DBUILD_REST_SERVER=ON && cmake --build \"$BUILD_DIR\" -j"
  exit 1
fi

echo "[smoke] starting uml001_rest_server"
"$SERVER_BIN" >/tmp/uml001_rest_server.log 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true' EXIT

sleep 1

echo "[smoke] GET /time/now"
NOW_CODE=$(curl -sS -o /tmp/uml001_now.json -w "%{http_code}" -H "X-API-Key: $API_KEY" "$BASE_URL/time/now")
if [[ "$NOW_CODE" != "200" ]]; then
  echo "FAIL /time/now expected 200 got $NOW_CODE"
  exit 1
fi
echo "OK /time/now -> 200"

echo "[smoke] POST /time/shared-state"
SHARED_BODY='{"monotonic_version":1,"warp_score":0.0,"shared_agreed_time":1700000000,"shared_applied_drift":0,"leader_system_time_at_sync":1700000000,"signature_hex":"deadbeef","leader_id":"leader-A","key_id":"k1"}'
SHARED_CODE=$(curl -sS -o /tmp/uml001_shared.json -w "%{http_code}" -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -d "$SHARED_BODY" "$BASE_URL/time/shared-state")
if [[ "$SHARED_CODE" != "200" && "$SHARED_CODE" != "403" ]]; then
  echo "FAIL /time/shared-state expected 200 or 403 got $SHARED_CODE"
  exit 1
fi
echo "OK /time/shared-state -> $SHARED_CODE"

echo "[smoke] done"
