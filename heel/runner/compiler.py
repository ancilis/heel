"""Deterministic local compiler for immutable Heel canary rehearsals."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from heel.canary_contracts import (
    APPROVAL_PROJECTION_SCHEMA,
    TEST_MANIFEST_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_test_manifest,
)

from .catalog import CATALOG, CATALOG_BY_ID, CATALOG_IDS
from .openapi_routes import RouteInventory
from .store import UnsupportedSecureStorageError


BUDGETS = {
    "maximum_requests": 20,
    "maximum_concurrency": 1,
    "action_timeout_ms": 5000,
    "wall_timeout_ms": 60000,
    "maximum_response_bytes": 256 * 1024,
}
RETRY_POLICY = {
    "maximum_retries": 1,
    "retryable_failure_codes": ["connect_error", "timeout"],
}
LOCAL_EVIDENCE_RETENTION_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class CompileResult:
    manifest: dict[str, Any]
    projection: dict[str, Any]


def _mapping_table(value: Any) -> dict[str, Mapping[str, Any]]:
    if isinstance(value, Mapping):
        table = dict(value)
    elif isinstance(value, list):
        table = {
            item["scenario_id"]: item
            for item in value
            if isinstance(item, Mapping) and "scenario_id" in item
        }
        if len(table) != len(value):
            raise ValueError("scenario mappings must be unique objects")
    else:
        raise ValueError("explicit scenario mappings are required")
    if set(table) != set(CATALOG_IDS):
        raise ValueError("all four immutable launch scenarios must be mapped exactly once")
    if not all(isinstance(item, Mapping) for item in table.values()):
        raise ValueError("scenario mappings must be objects")
    return table


def _fixture_bindings(
    scenario_id: str,
    placeholders: list[str],
    fixture_ids: Mapping[str, Mapping[str, str]],
) -> list[dict[str, str]]:
    supplied = fixture_ids.get(scenario_id, {})
    if not isinstance(supplied, Mapping) or set(supplied) != set(placeholders):
        if placeholders or supplied:
            raise ValueError("exact local fixture bindings are required for every route placeholder")
        return []
    bindings = []
    for parameter_name in sorted(placeholders):
        fixture_id = supplied[parameter_name]
        if (
            type(fixture_id) is not str
            or not fixture_id
            or len(fixture_id.encode("utf-8")) > 128
            or any(ord(character) < 33 or ord(character) > 126 for character in fixture_id)
        ):
            raise ValueError("fixture IDs must be bounded local identifiers")
        bindings.append({"parameter_name": parameter_name, "fixture_id": fixture_id})
    return bindings


class CanaryCompiler:
    """Compile locally authoritative manifests and privacy-minimized approvals."""

    def __init__(self, signer=None, *, now_ms: int = 0, store=None, vault=None):
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("compile timestamp must be a non-negative integer")
        self.signer = signer
        self.now_ms = now_ms
        self.store = store
        self.vault = vault

    @staticmethod
    def inventory(specification: Mapping[str, Any]) -> RouteInventory:
        return RouteInventory(specification)

    def compile(
        self,
        specification: Mapping[str, Any],
        base: Mapping[str, Any],
        *,
        mappings: Any,
        credential_handle_ids: Mapping[str, str],
        fixture_ids: Mapping[str, Mapping[str, str]] | None = None,
        credential_labels: Mapping[str, str] | None = None,
        projection_id: str | None = None,
    ) -> CompileResult:
        del credential_labels  # Local labels are intentionally outside both contracts.
        return self.compile_routes(
            RouteInventory(specification).read_routes(),
            base,
            mappings=mappings,
            credential_handle_ids=credential_handle_ids,
            fixture_ids=fixture_ids,
            projection_id=projection_id,
        )

    def compile_routes(
        self,
        routes: list[Mapping[str, Any]],
        base: Mapping[str, Any],
        *,
        mappings: Any,
        credential_handle_ids: Mapping[str, str],
        fixture_ids: Mapping[str, Mapping[str, str]] | None = None,
        projection_id: str | None = None,
    ) -> CompileResult:
        if self.signer is None or not callable(getattr(self.signer, "sign", None)):
            raise ValueError("runner secure signer is required")
        key_id = getattr(self.signer, "key_id", None)
        if type(key_id) is not str or not key_id:
            raise ValueError("runner secure signer key ID is required")
        if not isinstance(base, Mapping):
            raise ValueError("manifest base must be an object")
        table = _mapping_table(mappings)
        route_table = {
            (route.get("method"), route.get("route_template")): route
            for route in routes if isinstance(route, Mapping)
        }
        if len(route_table) != len(routes):
            raise ValueError("route inventory must contain unique routes")
        fixture_ids = {} if fixture_ids is None else fixture_ids
        if not isinstance(fixture_ids, Mapping):
            raise ValueError("fixture bindings must be an object")
        if not set(fixture_ids) <= set(CATALOG_IDS):
            raise ValueError("fixture scenario is not in the immutable launch catalog")
        if not isinstance(credential_handle_ids, Mapping) or set(credential_handle_ids) != set(CATALOG_IDS):
            raise ValueError("all four semantic roles require exact local credential handles")

        scenarios: list[dict[str, Any]] = []
        actions: list[dict[str, Any]] = []
        credentials: list[dict[str, str]] = []
        for ordinal, catalog in enumerate(CATALOG):
            scenario_id = catalog["scenario_id"]
            mapping = table[scenario_id]
            minimal_fields = {"method", "route_template"}
            stored_fields = {
                "scenario_id", "method", "route_template", "semantic_auth_role",
                "auth_profile", "credential_handle_id", "fixture_bindings",
            }
            if set(mapping) not in {frozenset(minimal_fields), frozenset(stored_fields)}:
                raise ValueError("scenario mapping fields must match a closed local schema")
            if set(mapping) == stored_fields and (
                mapping["scenario_id"] != scenario_id
                or mapping["semantic_auth_role"] != catalog["semantic_auth_role"]
                or mapping["auth_profile"] != catalog["auth_profile"]
                or mapping["credential_handle_id"] != credential_handle_ids[scenario_id]
            ):
                raise ValueError("stored scenario mapping does not match the immutable catalog")
            method = mapping.get("method")
            route_template = mapping.get("route_template")
            if method not in {"GET", "HEAD"}:
                raise ValueError("canary mappings permit GET or HEAD only")
            route = route_table.get((method, route_template))
            if route is None:
                raise ValueError("mapped route is not present in the local read inventory")
            scenarios.append({
                "ordinal": ordinal,
                "scenario_id": scenario_id,
                "adapter_version": catalog["adapter_version"],
            })
            actions.append({
                "ordinal": ordinal,
                "scenario_id": scenario_id,
                "adapter_version": catalog["adapter_version"],
                "method": method,
                "route_template": route_template,
                "fixture_bindings": _fixture_bindings(
                    scenario_id, list(route.get("placeholders", [])), fixture_ids,
                ),
                "semantic_auth_role": catalog["semantic_auth_role"],
                "auth_profile": catalog["auth_profile"],
                "assertion_class": catalog["assertion_class"],
                "allowed_status_codes": list(catalog["allowed_status_codes"]),
                "allowed_body_shapes": list(catalog["allowed_body_shapes"]),
                "side_effect_class": "read_only",
            })
            credentials.append({
                "semantic_role": catalog["semantic_auth_role"],
                "credential_handle_id": credential_handle_ids[scenario_id],
                "auth_profile": catalog["auth_profile"],
            })
        credentials.sort(key=lambda item: (
            item["semantic_role"], item["auth_profile"], item["credential_handle_id"]
        ))

        try:
            workspace_id = base["workspace_id"]
            project_id = base["project_id"]
            environment = dict(base["environment"])
            runner_base = dict(base["runner"])
            compiler = dict(base["compiler"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("manifest base is incomplete") from None
        if runner_base.get("runner_key_id") != key_id:
            raise ValueError("runner signer does not match the manifest runner key")
        origin = environment.get("origin")
        split = urlsplit(origin) if isinstance(origin, str) else None
        if split is None or split.scheme != "https" or split.port is not None or not split.hostname:
            raise ValueError("manifest origin must be an exact HTTPS origin")

        manifest = {
            "schema_version": TEST_MANIFEST_SCHEMA,
            "workspace_id": workspace_id,
            "project_id": project_id,
            "environment": environment,
            "runner": runner_base,
            "compiler": compiler,
            "scenarios": scenarios,
            "actions": actions,
            "credential_bindings": credentials,
            "budgets": dict(BUDGETS),
            "egress": {
                "hostname": split.hostname,
                "port": 443,
                "redirect_policy": "deny",
            },
            "retry_policy": {
                "maximum_retries": RETRY_POLICY["maximum_retries"],
                "retryable_failure_codes": list(RETRY_POLICY["retryable_failure_codes"]),
            },
            "local_evidence_policy": {
                "retention_seconds": LOCAL_EVIDENCE_RETENTION_SECONDS,
            },
            "compiled_at_ms": self.now_ms,
        }
        manifest["manifest_digest"] = canonical_digest(manifest)
        manifest = validate_test_manifest(manifest)

        projection_actions = [
            {
                key: value for key, value in action.items()
                if key not in {"fixture_bindings", "auth_profile"}
            }
            for action in actions
        ]
        unsigned = {
            "schema_version": APPROVAL_PROJECTION_SCHEMA,
            "projection_id": projection_id or f"projection_{manifest['manifest_digest'][:24]}",
            "workspace_id": workspace_id,
            "project_id": project_id,
            "environment": environment,
            "runner": {
                "runner_id": runner_base["runner_id"],
                "runner_key_id": runner_base["runner_key_id"],
                "runner_version": runner_base["minimum_runner_version"],
                "adapter_versions": sorted({item["adapter_version"] for item in scenarios}),
            },
            "compiler": compiler,
            "scenarios": scenarios,
            "actions": projection_actions,
            "budgets": dict(BUDGETS),
            "egress": manifest["egress"],
            "retry_policy": manifest["retry_policy"],
            "compiled_at_ms": self.now_ms,
            "manifest_digest": manifest["manifest_digest"],
        }
        projection_digest = canonical_digest(unsigned)
        signature = self.signer.sign(canonical_bytes(unsigned))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("runner signer must return a 64-byte Ed25519 signature")
        projection = {
            **unsigned,
            "projection_digest": projection_digest,
            "signing_key_id": key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        projection = validate_approval_projection(projection)
        return CompileResult(manifest=manifest, projection=projection)

    def prepare_live(self) -> dict[str, bool]:
        if self.vault is None or getattr(self.vault, "supported", False) is not True:
            raise UnsupportedSecureStorageError(
                "live preparation requires a supported secure credential vault"
            )
        return {"prepared": True}
