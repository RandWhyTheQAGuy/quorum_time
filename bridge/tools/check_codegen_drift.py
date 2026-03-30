#!/usr/bin/env python3
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
from __future__ import annotations

import difflib
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    proto = repo_root / "bridge" / "proto" / "bridge.proto"
    checked_pb2 = repo_root / "bridge" / "bridge_pb2.py"
    checked_pb2_grpc = repo_root / "bridge" / "bridge_pb2_grpc.py"

    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        cmd = [
            sys.executable,
            "-m",
            "grpc_tools.protoc",
            f"-I{proto.parent}",
            f"--python_out={out}",
            f"--grpc_python_out={out}",
            str(proto),
        ]
        try:
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as exc:
            print(f"ERROR: protoc codegen failed: {exc}", file=sys.stderr)
            return 2

        gen_pb2 = out / "bridge_pb2.py"
        gen_pb2_grpc = out / "bridge_pb2_grpc.py"

        failed = False
        for checked, generated in [(checked_pb2, gen_pb2), (checked_pb2_grpc, gen_pb2_grpc)]:
            checked_lines = checked.read_text().splitlines(keepends=True)
            generated_lines = generated.read_text().splitlines(keepends=True)
            if checked_lines != generated_lines:
                failed = True
                print(f"Drift detected: {checked}")
                for line in difflib.unified_diff(
                    checked_lines,
                    generated_lines,
                    fromfile=str(checked),
                    tofile=str(generated),
                    n=2,
                ):
                    sys.stdout.write(line)
        if failed:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
