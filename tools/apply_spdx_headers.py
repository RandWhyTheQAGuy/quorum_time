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
# This file applies Quorum Time SPDX/copyright headers across the tree.
# Run: python3 tools/apply_spdx_headers.py [--dry-run]
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MARKER = "SPDX-License-Identifier: Apache-2.0"
COPYRIGHT = "Copyright 2026 Randy Spickler"

BODY_LINES = [
    "Quorum Time is an open, verifiable, Byzantine-resilient trusted-time",
    "system designed for modern distributed environments. It provides a",
    "cryptographically anchored notion of time that can be aligned,",
    "audited, and shared across domains without requiring centralized",
    "trust.",
    "",
    "This project also includes the Aegis Semantic Passport components,",
    "which complement Quorum Time by offering structured, verifiable",
    "identity and capability attestations for agents and services.",
    "",
    "Core capabilities:",
    "  - BFT Quorum Time: multi-authority, tamper-evident time agreement",
    "                     with drift bounds, authority attestation, and",
    "                     cross-domain alignment (AlignTime).",
    "",
    "  - Transparency Logging: append-only, hash-chained audit records",
    "                          for time events, alignment proofs, and",
    "                          key-rotation operations.",
    "",
    "  - Open Integration: designed for interoperability with distributed",
    "                      systems, security-critical infrastructure,",
    "                      autonomous agents, and research environments.",
    "",
    "Quorum Time is developed as an open-source project with a focus on",
    "clarity, auditability, and long-term maintainability. Contributions,",
    "issue reports, and discussions are welcome.",
    "",
    "Licensed under the Apache License, Version 2.0 (the \"License\").",
    "You may obtain a copy of the License at:",
    "",
    "    http://www.apache.org/licenses/LICENSE-2.0",
    "",
    "This implementation is intended for open research, practical",
    "deployment, and community-driven evolution of verifiable time and",
    "distributed trust standards.",
]

EXCLUDE_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "build",
        ".cursor",
        ".vscode",
        ".idea",
    }
)

EXCLUDE_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".so",
    ".dylib",
    ".a",
    ".o",
    ".bin",
)


def under_build(p: Path) -> bool:
    try:
        p.relative_to(ROOT / "build")
        return True
    except ValueError:
        return False


def should_skip_path(p: Path) -> bool:
    if under_build(p):
        return True
    for part in p.parts:
        if part in EXCLUDE_DIR_NAMES:
            return True
    if p.suffix.lower() in EXCLUDE_SUFFIXES:
        return True
    name = p.name
    if name.endswith("_pb2.py") or name.endswith("_pb2_grpc.py"):
        return True
    if name in {
        "signed_state.pb.h",
        "signed_state.pb.cc",
        "signed_state.grpc.pb.h",
        "signed_state.grpc.pb.cc",
    }:
        return True
    return False


def has_header(text: str) -> bool:
    return MARKER in text or COPYRIGHT in text


def c_block() -> str:
    lines = [
        "/*",
        " * Quorum Time — Open Trusted Time & Distributed Verification Framework",
        f" * {COPYRIGHT} (github.com/RandWhyTheQAGuy)",
        f" * {MARKER}",
        " *",
    ]
    for bl in BODY_LINES:
        lines.append(" *" if bl == "" else " * " + bl)
    lines.extend([" */", ""])
    return "\n".join(lines)


def hash_block() -> str:
    lines = [
        "# Quorum Time — Open Trusted Time & Distributed Verification Framework",
        f"# {COPYRIGHT} (github.com/RandWhyTheQAGuy)",
        f"# {MARKER}",
        "#",
    ]
    for bl in BODY_LINES:
        lines.append("#" if bl == "" else "# " + bl)
    lines.append("#")
    lines.append("")
    return "\n".join(lines)


def proto_block() -> str:
    lines = [
        "// Quorum Time — Open Trusted Time & Distributed Verification Framework",
        f"// {COPYRIGHT} (github.com/RandWhyTheQAGuy)",
        f"// {MARKER}",
        "//",
    ]
    for bl in BODY_LINES:
        lines.append("//" if bl == "" else "// " + bl)
    lines.append("//")
    lines.append("")
    return "\n".join(lines)


def md_html_comment() -> str:
    lines = [
        "<!--",
        "  Quorum Time — Open Trusted Time & Distributed Verification Framework",
        f"  {COPYRIGHT} (github.com/RandWhyTheQAGuy)",
        f"  {MARKER}",
        "",
    ]
    for bl in BODY_LINES:
        lines.append("  " + bl if bl else "")
    lines.extend(["", "-->", ""])
    return "\n".join(lines)


def split_shebang(raw: str) -> tuple[str, str]:
    if raw.startswith("#!"):
        nl = raw.find("\n")
        if nl != -1:
            return raw[: nl + 1], raw[nl + 1 :]
    return "", raw


def merge_json_license(raw: str) -> str | None:
    stripped = raw.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if "$comment" in data and MARKER in str(data.get("$comment", "")):
        return None
    comment = (
        "Quorum Time — Open Trusted Time & Distributed Verification Framework. "
        + COPYRIGHT
        + " (github.com/RandWhyTheQAGuy). "
        + MARKER
    )
    merged = {"$comment": comment, **data}
    return json.dumps(merged, indent=2, ensure_ascii=False) + "\n"


def process_file(path: Path, dry_run: bool) -> bool:
    try:
        raw = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False

    if has_header(raw):
        return False

    ext = path.suffix.lower()
    name = path.name

    if ext in {".cpp", ".cc", ".c", ".h", ".hpp", ".inl"}:
        new_text = c_block() + raw
    elif ext == ".py":
        shebang, body = split_shebang(raw)
        new_text = shebang + hash_block() + body
    elif ext == ".sh" or name in {"build.sh", "build_python.sh", "build_sdk.sh"}:
        shebang, body = split_shebang(raw)
        new_text = shebang + hash_block() + body
    elif ext == ".proto":
        new_text = proto_block() + raw
    elif name.lower() == "cmakelists.txt":
        new_text = hash_block() + raw
    elif ext == ".md":
        # Keep Apache LICENSE text machine-parseable (plain text header only).
        if name.upper() == "LICENSE.MD":
            return False
        new_text = md_html_comment() + raw
    elif ext == ".json":
        merged = merge_json_license(raw)
        if merged is None:
            return False
        new_text = merged
    elif ext in {".yml", ".yaml"}:
        new_text = hash_block() + raw
    elif name == "Dockerfile" or name.endswith(".dockerfile"):
        new_text = hash_block() + raw
    elif ext == ".jsonl":
        return False
    else:
        return False

    if not dry_run:
        path.write_text(new_text, encoding="utf-8")
    return True


def main() -> int:
    dry = "--dry-run" in sys.argv
    exts = {
        ".cpp",
        ".cc",
        ".c",
        ".h",
        ".hpp",
        ".inl",
        ".py",
        ".sh",
        ".proto",
        ".md",
        ".json",
        ".yml",
        ".yaml",
    }
    extra_names = {"CMakeLists.txt", "Dockerfile", "build.sh", "build_python.sh", "build_sdk.sh"}

    changed = 0
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIR_NAMES and d != "build"]
        for fn in filenames:
            p = Path(dirpath) / fn
            if should_skip_path(p):
                continue
            if p.suffix.lower() not in exts and fn not in extra_names:
                continue
            if fn == "apply_spdx_headers.py":
                continue
            scanned += 1
            if process_file(p, dry):
                changed += 1
                print(("would write " if dry else "updated ") + str(p.relative_to(ROOT)))

    print(f"Done. scanned={scanned} changed={changed} dry_run={dry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
