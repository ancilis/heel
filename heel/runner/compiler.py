"""Deterministic local compiler for immutable differential canary rehearsals."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from heel.canary_contracts import (
    APPROVAL_PROJECTION_SCHEMA,
    TEST_MANIFEST_SCHEMA,
    canonical_bytes,
    canonical_digest,
    validate_approval_projection,
    validate_test_manifest,
)
from heel.runner.identity import RunnerIdentity, SecureSigner

from .catalog import CATALOG_BY_ID, CATALOG_IDS
from .openapi_routes import RouteInventory
from .store import RunnerStore, UnsupportedSecureStorageError
from .vault import EphemeralVault, VaultUnavailable, validate_credential_secret


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
COMPILER_VERSION = "1"
ENGINE_VERSION = "1"


@dataclass(frozen=True)
class CompileResult:
    manifest: dict[str, Any]
    projection: dict[str, Any]


def _selected_scenarios(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("selected scenarios must be an ordered subset")
    selected = tuple(value)
    if not selected or len(selected) > len(CATALOG_IDS):
        raise ValueError("selected scenarios must be a nonempty ordered subset")
    if any(type(item) is not str or item not in CATALOG_BY_ID for item in selected):
        raise ValueError("unknown launch scenario")
    if len(set(selected)) != len(selected):
        raise ValueError("selected scenarios must be unique")
    expected = tuple(item for item in CATALOG_IDS if item in set(selected))
    if selected != expected:
        raise ValueError("selected scenarios must retain catalog order")
    return selected


def _binding_identity(identity: RunnerIdentity) -> dict[str, Any]:
    return {
        "runner_id": identity.runner_id,
        "workspace_id": identity.workspace_id,
        "runner_version": identity.runner_version,
        "adapter_versions": dict(sorted(identity.adapter_versions.items())),
        "public_key_b64": identity.public_key_b64,
        "fingerprint": identity.fingerprint,
        "runner_key_id": identity.key_id,
    }


class CanaryCompiler:
    """Compile only state already pinned to one local context and runner identity."""

    def __init__(
        self,
        *,
        store: RunnerStore,
        identity: RunnerIdentity,
        signer: SecureSigner,
        now_ms: int = 0,
    ):
        if not isinstance(store, RunnerStore):
            raise ValueError("context-bound RunnerStore is required")
        if not isinstance(identity, RunnerIdentity) or not isinstance(signer, SecureSigner):
            raise ValueError("actual paired runner identity and signer are required")
        if isinstance(now_ms, bool) or not isinstance(now_ms, int) or now_ms < 0:
            raise ValueError("compile timestamp must be a non-negative integer")
        try:
            public_key = base64.b64decode(identity.public_key_b64, validate=True)
        except (TypeError, ValueError):
            raise ValueError("runner identity public key is invalid") from None
        if signer.key_id != identity.key_id or signer.public_key != public_key:
            raise ValueError("runner signer does not match paired identity")
        expected_versions = {
            scenario_id: CATALOG_BY_ID[scenario_id]["adapter_version"]
            for scenario_id in CATALOG_IDS
        }
        if dict(identity.adapter_versions) != expected_versions:
            raise ValueError("runner adapter version does not match launch catalog")
        binding = store.load_binding()
        if binding["identity"] != _binding_identity(identity):
            raise ValueError("runner identity does not match bound context")
        self.store = store
        self.identity = identity
        self.signer = signer
        self.now_ms = now_ms

    @staticmethod
    def inventory(specification: Mapping[str, Any]) -> RouteInventory:
        return RouteInventory(specification)

    def _inputs(
        self, selected: tuple[str, ...],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        mappings = {item["scenario_id"]: item for item in self.store.list_mappings()}
        credentials = {
            item["semantic_role"]: item
            for item in self.store.list_credentials()
            if item["state"] == "active"
        }
        missing = [scenario_id for scenario_id in selected if scenario_id not in mappings]
        if missing:
            raise ValueError("every selected scenario requires an explicit mapping")
        return mappings, credentials

    def compile(
        self,
        selected_scenarios: Sequence[str],
        *,
        projection_id: str | None = None,
        persist: bool = True,
    ) -> CompileResult:
        selected = _selected_scenarios(selected_scenarios)
        mappings, credential_records = self._inputs(selected)
        context = self.store.load_context()

        scenarios: list[dict[str, Any]] = []
        actions: list[dict[str, Any]] = []
        credentials: dict[str, dict[str, str]] = {}
        for scenario_ordinal, scenario_id in enumerate(selected):
            catalog = CATALOG_BY_ID[scenario_id]
            mapping = mappings[scenario_id]
            method = mapping["method"]
            if method not in catalog["allowed_methods"]:
                suffix = "GET only" if catalog["allowed_methods"] == ("GET",) else "GET or HEAD"
                raise ValueError(f"scenario mapping permits {suffix}")
            roles = catalog["semantic_roles"]
            role_records: dict[str, dict[str, Any]] = {}
            for role in roles:
                if role == "anonymous":
                    continue
                record = credential_records.get(role)
                if record is None:
                    raise ValueError("every nonanonymous semantic role requires a credential")
                role_records[role] = record
            selected_profiles = {record["auth_profile"] for record in role_records.values()}
            if len(selected_profiles) != 1:
                raise ValueError("comparison roles require the same nonanonymous auth profile")
            profile = next(iter(selected_profiles))
            fixture_bindings = [dict(item) for item in mapping["fixture_bindings"]]
            scenarios.append({
                "ordinal": scenario_ordinal,
                "scenario_id": scenario_id,
                "adapter_version": catalog["adapter_version"],
            })
            for role in roles:
                auth_profile = "anonymous" if role == "anonymous" else profile
                actions.append({
                    "ordinal": len(actions),
                    "scenario_id": scenario_id,
                    "adapter_version": catalog["adapter_version"],
                    "method": method,
                    "route_template": mapping["route_template"],
                    "fixture_bindings": [dict(item) for item in fixture_bindings],
                    "semantic_auth_role": role,
                    "auth_profile": auth_profile,
                    "assertion_class": catalog["assertion_class"],
                    "allowed_status_codes": list(catalog["allowed_status_codes"]),
                    "allowed_body_shapes": list(catalog["allowed_body_shapes"]),
                    "side_effect_class": catalog["side_effect_class"],
                })
                if role != "anonymous":
                    record = role_records[role]
                    credentials[role] = {
                        "semantic_role": role,
                        "credential_handle_id": record["credential_handle_id"],
                        "auth_profile": record["auth_profile"],
                    }

        environment = {
            "environment_id": context.environment_id,
            "verification_record_digest": context.verification_record_digest,
            "origin": context.origin,
            "environment_class": context.environment_class,
        }
        hostname = urlsplit(context.origin).hostname
        assert hostname is not None
        runner = {
            "runner_id": self.identity.runner_id,
            "runner_key_id": self.identity.key_id,
            "minimum_runner_version": self.identity.runner_version,
        }
        compiler = {
            "compiler_version": COMPILER_VERSION,
            "engine_version": ENGINE_VERSION,
        }
        manifest: dict[str, Any] = {
            "schema_version": TEST_MANIFEST_SCHEMA,
            "workspace_id": context.workspace_id,
            "project_id": context.project_id,
            "environment": environment,
            "runner": runner,
            "compiler": compiler,
            "scenarios": scenarios,
            "actions": actions,
            "credential_bindings": sorted(
                credentials.values(),
                key=lambda item: (
                    item["semantic_role"], item["auth_profile"], item["credential_handle_id"],
                ),
            ),
            "budgets": dict(BUDGETS),
            "egress": {
                "hostname": hostname,
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

        projection_actions = [{
            key: value
            for key, value in action.items()
            if key not in {"fixture_bindings", "auth_profile"}
        } for action in actions]
        unsigned = {
            "schema_version": APPROVAL_PROJECTION_SCHEMA,
            "projection_id": projection_id or f"projection_{manifest['manifest_digest'][:24]}",
            "workspace_id": context.workspace_id,
            "project_id": context.project_id,
            "environment": environment,
            "runner": {
                "runner_id": self.identity.runner_id,
                "runner_key_id": self.identity.key_id,
                "runner_version": self.identity.runner_version,
                "adapter_versions": sorted({
                    self.identity.adapter_versions[scenario_id] for scenario_id in selected
                }),
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
        signature = self.signer.sign(canonical_bytes(unsigned))
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ValueError("runner signer must return a 64-byte Ed25519 signature")
        projection = {
            **unsigned,
            "projection_digest": canonical_digest(unsigned),
            "signing_key_id": self.identity.key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }
        projection = validate_approval_projection(projection)
        result = CompileResult(manifest=manifest, projection=projection)
        if persist:
            self.store.save_approved_pair(manifest, projection)
        return result

    def prepare_live(
        self,
        selected_scenarios: Sequence[str],
        *,
        vaults: Mapping[str, object] | None = None,
    ) -> dict[str, int]:
        selected = _selected_scenarios(selected_scenarios)
        _, records = self._inputs(selected)
        context = self.store.load_context()
        vaults = {} if vaults is None else vaults
        required_roles = {
            role
            for scenario_id in selected
            for role in CATALOG_BY_ID[scenario_id]["semantic_roles"]
            if role != "anonymous"
        }
        try:
            for role in sorted(required_roles):
                record = records.get(role)
                if record is None:
                    raise VaultUnavailable("credential metadata is unavailable")
                if record["backend"] in {"ephemeral_env", "ephemeral_fd"}:
                    vault = EphemeralVault(
                        record["credential_handle_id"], source_kind=record["source_kind"],
                    )
                else:
                    vault = vaults.get(record["backend"])
                    if (
                        vault is None
                        or getattr(vault, "supported", False) is not True
                        or getattr(vault, "backend_id", None) != record["backend"]
                    ):
                        raise VaultUnavailable("credential backend is unavailable")
                secret = vault.load(record["credential_handle_id"])
                validate_credential_secret(record["auth_profile"], secret, context.origin)
                secret = b""
        except (ValueError, VaultUnavailable):
            raise UnsupportedSecureStorageError(
                "every live comparison credential must resolve from its exact secure backend"
            ) from None
        return {"credential_count": len(required_roles)}
