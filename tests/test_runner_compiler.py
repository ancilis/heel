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
from heel.runner.catalog import (
    AUTH_PROFILES,
    CATALOG,
    CATALOG_IDS,
    SEMANTIC_ROLES,
)
from heel.runner.compiler import CanaryCompiler
from heel.runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from heel.runner.openapi_routes import RouteInventory
from heel.runner.store import RunnerContext, RunnerStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/canary/staging-openapi.json"


class FixedSigner(SecureSigner):
    def __init__(self, seed: bytes = bytes(range(32))):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return self._private.sign(payload)


def identity(signer: FixedSigner, workspace_id: str = "ws_123456789") -> RunnerIdentity:
    return RunnerIdentity(
        runner_id="runner_123456789",
        workspace_id=workspace_id,
        runner_version="1",
        adapter_versions={scenario_id: "1" for scenario_id in CATALOG_IDS},
        public_key_b64=base64.b64encode(signer.public_key).decode("ascii"),
        fingerprint=__import__("hashlib").sha256(signer.public_key).hexdigest(),
        key_id=signer.key_id,
        pairing_phrase=runner_phrase_words()[:6],
    )


def context(environment_id: str = "env_123456789") -> RunnerContext:
    return RunnerContext(
        workspace_id="ws_123456789",
        project_id="prj_123456789",
        environment_id=environment_id,
        origin="https://staging.acme.dev",
        verification_record_digest="0" * 64,
        environment_class="staging",
    )


def specification():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def bound_store(tmp_path, *, selected_context=None, selected_signer=None):
    signer = selected_signer or FixedSigner()
    selected_context = selected_context or context()
    runner_identity = identity(signer, selected_context.workspace_id)
    store = RunnerStore(tmp_path / "heel-home")
    store.bind_context(
        selected_context,
        identity=runner_identity,
        signer=signer,
        signer_label="runner-test-key",
    )
    inventory = RouteInventory(specification())
    store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
    return store, runner_identity, signer


def map_scenarios(store: RunnerStore):
    store.save_mapping(
        "anonymous_authenticated_read", method="HEAD", route_template="/health",
    )
    store.save_mapping(
        "object_ownership_read",
        method="GET",
        route_template="/items/{item_id}",
        fixture_bindings={"item_id": "canary-a-item-0137"},
    )


def add_roles(store: RunnerStore):
    for role in ("authenticated", "object_owner", "non_owner"):
        store.register_ephemeral_credential(
            semantic_role=role,
            auth_profile="bearer",
            source_kind="environment",
            label=f"local {role}",
        )


def test_catalog_has_exact_differential_roles_methods_and_closed_auth_profiles():
    assert CATALOG_IDS == (
        "anonymous_authenticated_read",
        "object_ownership_read",
        "role_bound_read",
        "plan_entitlement_read",
    )
    assert SEMANTIC_ROLES == frozenset({
        "anonymous", "authenticated", "object_owner", "non_owner",
        "lower_privilege", "higher_privilege", "lower_plan", "higher_plan",
    })
    assert AUTH_PROFILES == frozenset({"anonymous", "bearer", "cookie_jar", "x_api_key"})
    assert [entry["semantic_roles"] for entry in CATALOG] == [
        ("anonymous", "authenticated"),
        ("object_owner", "non_owner"),
        ("lower_privilege", "higher_privilege"),
        ("lower_plan", "higher_plan"),
    ]
    assert CATALOG[0]["allowed_methods"] == ("GET", "HEAD")
    assert all(entry["allowed_methods"] == ("GET",) for entry in CATALOG[1:])
    assert all(entry["side_effect_class"] == "read_only" for entry in CATALOG)
    with pytest.raises(TypeError):
        CATALOG[0]["semantic_roles"] = ("invented",)  # type: ignore[index]


def test_inventory_is_product_model_derived_and_rejects_hostile_route_forms():
    entries = RouteInventory(specification()).read_routes()
    assert [(item["method"], item["route_template"]) for item in entries] == [
        ("GET", "/admin/users"),
        ("GET", "/billing/features"),
        ("GET", "/health"),
        ("HEAD", "/health"),
        ("GET", "/items"),
        ("GET", "/items/{item_id}"),
    ]

    for route in (
        "/percent%2fescape", "/back\\slash", "/a/../b", "/a/./b", "/a//b",
        "/query?x=1", "/fragment#x", "/bad/{id}/{id}", "/bad/{not-balanced",
        "/bad/{" + "x" * 65 + "}", "/control\x00value",
    ):
        spec = specification()
        spec["paths"] = {route: {"get": {"operationId": "hostile"}}}
        with pytest.raises(ValueError, match="route"):
            RouteInventory(spec)


def test_store_revalidates_route_and_mapping_files_at_the_corruption_boundary(tmp_path):
    store, _, _ = bound_store(tmp_path)
    context_dir = tmp_path / "heel-home" / "runner" / "contexts" / store.namespace
    routes_path = context_dir / "routes.json"
    routes_value = json.loads(routes_path.read_text(encoding="utf-8"))
    routes_value["inventory"]["routes"][0]["route_template"] = "/bad%2froute"
    routes_path.write_text(
        json.dumps(routes_value, sort_keys=True, separators=(",", ":")), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="route"):
        store.list_routes()

    second, _, _ = bound_store(tmp_path / "second")
    second.save_mapping(
        "anonymous_authenticated_read", method="GET", route_template="/health",
    )
    second_dir = (
        tmp_path / "second" / "heel-home" / "runner" / "contexts" / second.namespace
    )
    mappings_path = second_dir / "mappings.json"
    mappings_value = json.loads(mappings_path.read_text(encoding="utf-8"))
    mappings_value["mappings"][0]["method"] = "POST"
    mappings_path.write_text(
        json.dumps(mappings_value, sort_keys=True, separators=(",", ":")), encoding="utf-8",
    )
    with pytest.raises(ValueError, match="method"):
        second.list_mappings()


def test_context_namespace_and_binding_are_exact_and_cross_context_rebind_fails(tmp_path):
    store, runner_identity, signer = bound_store(tmp_path)
    expected = __import__("hashlib").sha256(
        b"ws_123456789\0prj_123456789\0env_123456789"
    ).hexdigest()
    assert store.namespace == expected
    assert store.load_context() == context()

    other_context = context("env_other_123")
    other_signer = FixedSigner(bytes(reversed(range(32))))
    other_identity = identity(other_signer, other_context.workspace_id)
    with pytest.raises(ValueError, match="bound context"):
        CanaryCompiler(
            store=store,
            identity=other_identity,
            signer=other_signer,
            now_ms=7,
        )
    same_namespace_other_target = RunnerContext(
        workspace_id="ws_123456789",
        project_id="prj_123456789",
        environment_id="env_123456789",
        origin="https://other.acme.dev",
        verification_record_digest="1" * 64,
        environment_class="staging",
    )
    with pytest.raises(ValueError, match="cannot be rebound"):
        store.bind_context(
            same_namespace_other_target,
            identity=runner_identity,
            signer=signer,
            signer_label="runner-test-key",
        )
    assert store.load_context() == context()
    assert runner_identity.key_id == signer.key_id


def test_selected_subset_compiles_true_two_action_differentials_and_persists_pair(tmp_path):
    store, runner_identity, signer = bound_store(tmp_path)
    map_scenarios(store)
    add_roles(store)
    compiler = CanaryCompiler(
        store=store, identity=runner_identity, signer=signer, now_ms=1_700_000_000_000,
    )
    result = compiler.compile([
        "anonymous_authenticated_read",
        "object_ownership_read",
    ], projection_id="projection_123456789")

    manifest = validate_test_manifest(result.manifest)
    projection = validate_approval_projection(result.projection)
    assert [item["scenario_id"] for item in manifest["scenarios"]] == [
        "anonymous_authenticated_read", "object_ownership_read",
    ]
    assert len(manifest["actions"]) == 4
    assert [item["semantic_auth_role"] for item in manifest["actions"]] == [
        "anonymous", "authenticated", "object_owner", "non_owner",
    ]
    assert [item["auth_profile"] for item in manifest["actions"]] == [
        "anonymous", "bearer", "bearer", "bearer",
    ]
    assert manifest["actions"][0]["route_template"] == manifest["actions"][1]["route_template"]
    assert manifest["actions"][2]["fixture_bindings"] == manifest["actions"][3]["fixture_bindings"]
    assert {item["semantic_role"] for item in manifest["credential_bindings"]} == {
        "authenticated", "object_owner", "non_owner",
    }
    assert "anonymous" not in {
        item["semantic_role"] for item in manifest["credential_bindings"]
    }
    assert projection["runner"] == {
        "runner_id": runner_identity.runner_id,
        "runner_key_id": runner_identity.key_id,
        "runner_version": runner_identity.runner_version,
        "adapter_versions": ["1"],
    }

    unsigned = {
        key: value for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    assert signer.payloads[-1] == canonical_bytes(unsigned)
    # Binding the fresh runner context persists both signed zero authority
    # roots (index and checkpoint) before the compiler signs manifest and
    # approval projection.
    assert len(signer.payloads) == 4
    assert signer.payloads[0].startswith(b"heel.local-run-authority-index.v1\0")
    loaded_manifest, loaded_projection = store.load_approved_pair("projection_123456789")
    assert loaded_manifest == manifest
    assert loaded_projection == projection


def test_projection_recursively_excludes_handles_fixtures_labels_and_openapi(tmp_path):
    store, runner_identity, signer = bound_store(tmp_path)
    map_scenarios(store)
    add_roles(store)
    result = CanaryCompiler(
        store=store, identity=runner_identity, signer=signer, now_ms=7,
    ).compile(["anonymous_authenticated_read", "object_ownership_read"])

    projection_text = canonical_bytes(result.projection).decode("utf-8")
    manifest_text = canonical_bytes(result.manifest).decode("utf-8")
    for record in store.list_credentials():
        assert record["credential_handle_id"] not in projection_text
        assert record["label"] not in projection_text
        assert record["credential_handle_id"] in manifest_text
    assert "canary-a-item-0137" not in projection_text
    assert "canary-a-item-0137" in manifest_text
    assert "openapi" not in projection_text.lower()


def test_compile_rejects_wrong_method_missing_roles_profile_mismatch_and_versions(tmp_path):
    store, runner_identity, signer = bound_store(tmp_path)
    store.save_mapping(
        "object_ownership_read", method="HEAD", route_template="/health",
    )
    compiler = CanaryCompiler(store=store, identity=runner_identity, signer=signer, now_ms=7)
    with pytest.raises(ValueError, match="GET only"):
        compiler.compile(["object_ownership_read"])

    store.save_mapping(
        "object_ownership_read", method="GET", route_template="/items/{item_id}",
        fixture_bindings={"item_id": "local-item"},
    )
    with pytest.raises(ValueError, match="requires a credential"):
        compiler.compile(["object_ownership_read"])
    for role, profile in (
        ("object_owner", "bearer"),
        ("non_owner", "x_api_key"),
    ):
        store.register_ephemeral_credential(
            semantic_role=role, auth_profile=profile,
            source_kind="environment", label=role,
        )
    with pytest.raises(ValueError, match="same nonanonymous auth profile"):
        compiler.compile(["object_ownership_read"])

    wrong_versions = copy.deepcopy(runner_identity.adapter_versions)
    wrong_versions["object_ownership_read"] = "2"
    wrong_identity = copy.copy(runner_identity)
    object.__setattr__(wrong_identity, "adapter_versions", wrong_versions)
    with pytest.raises(ValueError, match="adapter version"):
        CanaryCompiler(store=store, identity=wrong_identity, signer=signer, now_ms=7)


def test_compilation_is_deterministic_for_explicit_state(tmp_path):
    store, runner_identity, signer = bound_store(tmp_path)
    map_scenarios(store)
    add_roles(store)
    first = CanaryCompiler(
        store=store, identity=runner_identity, signer=signer, now_ms=7,
    ).compile(["anonymous_authenticated_read", "object_ownership_read"], persist=False)
    signer.payloads.clear()
    second = CanaryCompiler(
        store=store, identity=runner_identity, signer=signer, now_ms=7,
    ).compile(["anonymous_authenticated_read", "object_ownership_read"], persist=False)
    assert first == second
