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

import json
import re
from pathlib import Path

import pytest


def _validator_for(schema: dict, *, base_uri: str | None = None):
    import jsonschema
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    if base_uri:
        from jsonschema import RefResolver
        resolver = RefResolver(base_uri=base_uri, referrer=schema)
        return lambda s: cls(s, resolver=resolver)
    return cls


def test_catalog_schemas_are_valid_json_schema_documents():
    jsonschema = pytest.importorskip("jsonschema")
    assert jsonschema is not None
    root = Path(__file__).resolve().parents[1]
    catalog = json.loads((root / "spec/schemas/catalog.json").read_text())

    for entry in catalog["schemas"]:
        schema_path = root / "spec/schemas" / entry["path"]
        schema = json.loads(schema_path.read_text())
        _validator_for(schema)


def test_canonical_examples_validate_against_primary_contracts():
    jsonschema = pytest.importorskip("jsonschema")
    assert jsonschema is not None
    root = Path(__file__).resolve().parents[1]
    schemas = {
        "event_context": json.loads((root / "spec/schemas/event_context.schema.json").read_text()),
        "signed_state": json.loads((root / "spec/schemas/signed_state_envelope.schema.json").read_text()),
        "bft_shared_state": json.loads((root / "spec/schemas/bft_shared_state.schema.json").read_text()),
    }
    base_uri = (root / "spec/schemas").resolve().as_uri() + "/"
    validators = {k: _validator_for(v, base_uri=base_uri)(v) for k, v in schemas.items()}

    mapping = {
        "event_context.minimal.json": "event_context",
        "event_context.aborted.hitl_hold.json": "event_context",
        "signed_state.control_set_mode.json": "signed_state",
        "signed_state.rest_time_now.json": "signed_state",
        "signed_state.worker_ntp_sync.json": "signed_state",
        "signed_state.internal_shared_state_apply.json": "signed_state",
        "signed_state.rest_auth_failed.json": "signed_state",
        "bft_shared_state.rest_time_shared_state.json": "bft_shared_state",
    }

    for filename, schema_key in mapping.items():
        instance = json.loads((root / "spec/examples/canonical" / filename).read_text())
        validators[schema_key].validate(instance)


def test_signed_state_schema_proto_semantic_parity_and_encoding():
    pytest.importorskip("jsonschema")
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "spec/schemas/signed_state_envelope.schema.json").read_text())
    proto = (root / "proto/signed_state.proto").read_text()

    # SignedState field parity.
    expected_fields = [
        "logical_time_ns",
        "event_id",
        "payload",
        "signature",
        "key_id",
        "gossip",
        "anchor_proof",
    ]
    props = schema["properties"]
    for f in expected_fields:
        assert f in props
        assert re.search(rf"\b{f}\s*=\s*\d+;", proto), f"Missing proto field: {f}"

    # GossipState nested parity.
    expected_gossip = ["hops", "ttl", "validated", "origin_node_id"]
    for f in expected_gossip:
        assert f in props["gossip"]["properties"]
        assert re.search(rf"\b{f}\s*=\s*\d+;", proto), f"Missing proto gossip field: {f}"

    # AnchorProof nested parity.
    expected_anchor = [
        "version",
        "is_merkle_root",
        "observation_hash",
        "quorum_size",
        "authority_set",
        "event_id",
        "event_hash",
    ]
    for f in expected_anchor:
        assert f in props["anchor_proof"]["properties"]
        assert re.search(rf"\b{f}\s*=\s*\d+;", proto), f"Missing proto anchor field: {f}"

    # Encoding strictness for proto bytes fields.
    for bytes_field in ("payload", "signature"):
        fld = props[bytes_field]
        assert fld.get("contentEncoding") == "base64"
        assert "pattern" in fld
