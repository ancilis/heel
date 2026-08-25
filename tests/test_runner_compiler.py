from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from heel.canary_contracts import (
    canonical_bytes,
    validate_approval_projection,
    validate_test_manifest,
)
from heel.crypto import ed25519_key_id
from heel.runner.catalog import AUTH_PROFILES, CATALOG, CATALOG_IDS
from heel.runner.compiler import CanaryCompiler
from heel.runner.identity import SecureSigner
from heel.runner.openapi_routes import RouteInventory


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/canary/staging-openapi.json"


class FixedSigner(SecureSigner):
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self._private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public_key = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)
        self.payloads = []

    def sign(self, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return self._private.sign(payload)


BASE = {
    "workspace_id": "ws_123456789",
    "project_id": "prj_123456789",
    "environment": {
        "environment_id": "env_123456789",
        "verification_record_digest": "0" * 64,
        "origin": "https://staging.acme.dev",
        "environment_class": "staging",
    },
    "runner": {
        "runner_id": "runner_123456789",
        "runner_key_id": "REPLACED",
        "minimum_runner_version": "1",
    },
    "compiler": {"compiler_version": "1", "engine_version": "1"},
}


def fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def mappings():
    return {
        "anonymous_authenticated_read": {"method": "HEAD", "route_template": "/health"},
        "object_ownership_read": {"method": "GET", "route_template": "/items/{item_id}"},
        "role_bound_read": {"method": "GET", "route_template": "/admin/users"},
        "plan_entitlement_read": {"method": "GET", "route_template": "/billing/features"},
    }


def handles():
    return {
        scenario_id: f"{index:032x}"
        for index, scenario_id in enumerate(CATALOG_IDS, start=1)
    }


def base(signer):
    value = copy.deepcopy(BASE)
    value["runner"]["runner_key_id"] = signer.key_id
    return value


def test_catalog_is_exact_immutable_and_read_only():
    assert CATALOG_IDS == (
        "anonymous_authenticated_read",
        "object_ownership_read",
        "role_bound_read",
        "plan_entitlement_read",
    )
    assert AUTH_PROFILES == frozenset({"anonymous", "bearer", "cookie_jar", "x_api_key"})
    assert tuple(entry["scenario_id"] for entry in CATALOG) == CATALOG_IDS
    assert {entry["auth_profile"] for entry in CATALOG} == AUTH_PROFILES
    assert all(entry["side_effect_class"] == "read_only" for entry in CATALOG)
    assert all(set(entry) == {
        "ordinal", "scenario_id", "adapter_version", "semantic_auth_role",
        "auth_profile", "assertion_class", "allowed_status_codes",
        "allowed_body_shapes", "side_effect_class",
    } for entry in CATALOG)


def test_inventory_is_derived_from_product_model_and_only_contains_get_head():
    entries = RouteInventory(fixture()).read_routes()
    assert [(entry["method"], entry["route_template"]) for entry in entries] == [
        ("GET", "/admin/users"),
        ("GET", "/billing/features"),
        ("GET", "/health"),
        ("HEAD", "/health"),
        ("GET", "/items"),
        ("GET", "/items/{item_id}"),
    ]
    assert entries[-1]["placeholders"] == ["item_id"]
    assert entries[-1]["operation_id"] == "getitem"
    assert "POST" not in canonical_bytes(entries).decode()


def test_inventory_accepts_nonsecret_numeric_openapi_schema_metadata():
    spec = fixture()
    spec["paths"]["/items"]["get"]["responses"]["200"]["content"] = {
        "application/json": {"schema": {"type": "number", "minimum": 0.5}}
    }
    assert RouteInventory(spec).read_routes()


def test_compiler_emits_valid_deterministic_full_manifest_and_signed_projection():
    signer = FixedSigner()
    compiler = CanaryCompiler(signer=signer, now_ms=1_700_000_000_000)
    result = compiler.compile(
        fixture(),
        base(signer),
        mappings=mappings(),
        credential_handle_ids=handles(),
        fixture_ids={"object_ownership_read": {"item_id": "canary-a-item-0137"}},
        projection_id="projection_123456789",
    )

    manifest = validate_test_manifest(result.manifest)
    projection = validate_approval_projection(result.projection)
    assert len(manifest["scenarios"]) == 4
    assert len(manifest["actions"]) == 4
    assert manifest["budgets"] == {
        "maximum_requests": 20,
        "maximum_concurrency": 1,
        "action_timeout_ms": 5000,
        "wall_timeout_ms": 60000,
        "maximum_response_bytes": 256 * 1024,
    }
    assert manifest["egress"] == {
        "hostname": "staging.acme.dev", "port": 443, "redirect_policy": "deny",
    }
    assert manifest["retry_policy"] == {
        "maximum_retries": 1,
        "retryable_failure_codes": ["connect_error", "timeout"],
    }
    assert result.projection["manifest_digest"] == result.manifest["manifest_digest"]

    unsigned = {
        key: value for key, value in result.projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    assert signer.payloads == [canonical_bytes(unsigned)]
    assert len(base64.b64decode(projection["signature_b64"], validate=True)) == 64


def test_projection_recursively_excludes_private_local_values_and_openapi_text():
    signer = FixedSigner()
    spec = fixture()
    spec["info"]["description"] = "RAW OPENAPI PRIVATE LABEL"
    result = CanaryCompiler(signer=signer, now_ms=7).compile(
        spec,
        base(signer),
        mappings=mappings(),
        credential_handle_ids=handles(),
        credential_labels={scenario_id: f"LOCAL LABEL {index}" for index, scenario_id in enumerate(CATALOG_IDS)},
        fixture_ids={"object_ownership_read": {"item_id": "LOCAL-FIXTURE-137"}},
    )

    projection_text = canonical_bytes(result.projection).decode("utf-8")
    for forbidden in (
        "credential_handle_id", "fixture_id", "LOCAL-FIXTURE-137",
        "LOCAL LABEL", "RAW OPENAPI PRIVATE LABEL", "components", "paths",
    ):
        assert forbidden not in projection_text
    assert "LOCAL-FIXTURE-137" in canonical_bytes(result.manifest).decode()


def test_compilation_is_deterministic_for_explicit_inputs():
    first_signer = FixedSigner()
    second_signer = FixedSigner()
    kwargs = {
        "mappings": mappings(),
        "credential_handle_ids": handles(),
        "fixture_ids": {"object_ownership_read": {"item_id": "local-item"}},
        "projection_id": "projection_123456789",
    }
    first = CanaryCompiler(first_signer, now_ms=7).compile(fixture(), base(first_signer), **kwargs)
    second = CanaryCompiler(second_signer, now_ms=7).compile(fixture(), base(second_signer), **kwargs)
    assert first == second


def test_compiler_rejects_unmapped_routes_mutations_and_missing_fixture_bindings():
    signer = FixedSigner()
    compiler = CanaryCompiler(signer, now_ms=7)
    bad = mappings()
    bad["role_bound_read"] = {"method": "POST", "route_template": "/items"}
    with pytest.raises(ValueError, match="GET or HEAD"):
        compiler.compile(
            fixture(), base(signer), mappings=bad, credential_handle_ids=handles(),
            fixture_ids={"object_ownership_read": {"item_id": "local-item"}},
        )

    missing = mappings()
    with pytest.raises(ValueError, match="fixture"):
        compiler.compile(fixture(), base(signer), mappings=missing, credential_handle_ids=handles())

    extra = mappings()
    extra["role_bound_read"] = {
        **extra["role_bound_read"],
        "headers": {"X-Invented": "must-not-be-accepted"},
    }
    with pytest.raises(ValueError, match="mapping fields"):
        compiler.compile(
            fixture(), base(signer), mappings=extra, credential_handle_ids=handles(),
            fixture_ids={"object_ownership_read": {"item_id": "local-item"}},
        )

    with pytest.raises(ValueError, match="fixture scenario"):
        compiler.compile(
            fixture(), base(signer), mappings=mappings(), credential_handle_ids=handles(),
            fixture_ids={
                "object_ownership_read": {"item_id": "local-item"},
                "invented_scenario": {},
            },
        )
