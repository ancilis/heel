"""Canonical, privacy-minimized contracts for verified canary execution.

The module deliberately validates only transport-safe projections: it has no network,
filesystem, crypto-provider, or application-model dependency.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

TEST_MANIFEST_SCHEMA = "heel.test-manifest.v1"
APPROVAL_PROJECTION_SCHEMA = "heel.approval-manifest-projection.v1"
RUNNER_IDENTITY_SCHEMA = "heel.runner-identity.v1"
EXECUTION_GRANT_SCHEMA = "heel.execution-grant.v1"
OPERATIONAL_RUN_SCHEMA = "heel.operational-run-projection.v1"
RUNNER_CLAIM_REQUEST_SCHEMA = "heel.runner-claim-request.v1"
RUNNER_HEARTBEAT_REQUEST_SCHEMA = "heel.runner-heartbeat-request.v1"
RUNNER_PROGRESS_REQUEST_SCHEMA = "heel.runner-progress-request.v1"
RUNNER_RESULT_REQUEST_SCHEMA = "heel.runner-result-request.v1"
RUNNER_STOP_ACK_REQUEST_SCHEMA = "heel.runner-stop-ack-request.v1"
CANARY_FINDINGS_SCHEMA = "heel.canary-findings-projection.v1"
DISCLOSURE_PERMIT_SCHEMA = "heel.disclosure-permit.v1"
RUNNER_CONTEXT_BINDING_SCHEMA = "heel.runner-context-binding.v1"
RUNNER_CONTEXT_BINDING_CREATE_SCHEMA = "heel.runner-context-binding-create.v1"
RUNNER_CONTEXT_BINDING_REVOKE_SCHEMA = "heel.runner-context-binding-revoke.v1"
RUNNER_CONTEXT_LIST_SCHEMA = "heel.runner-context-list.v1"
RUNNER_CONTEXT_CLAIM_SCHEMA = "heel.runner-context-claim.v1"
RUNNER_APPROVAL_PROJECTION_SUBMIT_SCHEMA = "heel.runner-approval-projection-submit.v1"
APPROVAL_PROJECTION_V2_SCHEMA = "heel.approval-manifest-projection.v2"
DISCOVERY_AUTHORIZATION_SCHEMA = "heel.discovery-authorization.v1"
DISCOVERY_ROUND_REPORT_SCHEMA = "heel.discovery-round-report.v1"
PLAN_REQUEST_SCHEMA = "heel.plan-request.v1"
RUNNER_PLAN_REQUEST_CLAIM_SCHEMA = "heel.runner-plan-request-claim.v1"
RUNNER_PLAN_REQUEST_SCHEMA = "heel.runner-plan-request.v1"
DISCOVERY_ACKNOWLEDGEMENT = "I authorize Heel to send up to 100 GET/HEAD requests to this origin"
# The fixed round-1 frontier.  Its digest is bound into every authorization and round-1 plan.
DISCOVERY_SEED_PATHS = (
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json", "/v3/api-docs",
    "/api-docs", "/api/openapi.json", "/api/swagger.json", "/.well-known/openapi", "/robots.txt",
    "/sitemap.xml", "/",
)
# Server constants, never client-settable.  The TTL is the authorization's expires_at_ms.
DISCOVERY_BOUND = {
    "max_rounds": 5, "max_actions_per_round": 20, "max_requests": 100,
    "max_total_execution_ms": 120_000, "max_wall_ms_per_round": 60_000, "max_body_bytes": 2_097_152,
}
DISCOVERY_PROVENANCE_KINDS = frozenset({
    "customer_url", "imported_openapi", "well_known_spec", "robots", "sitemap", "html_link",
    "script_src", "js_literal", "html_link_auth", "js_literal_auth", "redirect_location",
    "discovered_openapi",
})
# Kinds an executor may report from a round; customer and import sources are not round output.
_ROUND_PROVENANCE_KINDS = DISCOVERY_PROVENANCE_KINDS - {"customer_url", "imported_openapi"}
DISCOVERY_EXCLUDED_REASONS = frozenset({
    "method_not_allowed", "off_origin", "side_effect_risk", "static_asset", "truncated",
})

_SAFE_INT = (1 << 53) - 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_EVIDENCE = re.compile(r"^ev1_[0-9a-f]{64}$")
_DNS = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ROUTE = re.compile(r"^/[^\x00-\x1f\x7f]*$")
_FORBIDDEN_APPROVAL_KEYS = frozenset({
    "fixture_id", "fixture_bindings", "credential_handle", "credential_handle_id",
    "credential_bindings", "headers", "payload", "payloads", "script", "scripts",
    "shell", "model_output", "object_id", "object_ids", "query", "query_values",
    "raw_traffic", "cookies", "tokens", "local_path", "local_paths", "openapi",
    "raw_openapi", "paths", "components",
})
# Every C2 discovery/plan schema also refuses value-bearing names (discovery contract preamble).
_FORBIDDEN_DISCOVERY_KEYS = _FORBIDDEN_APPROVAL_KEYS | frozenset({
    "password", "secret", "token", "cookie", "authorization", "url", "query", "body",
})
_FORBIDDEN_OPERATIONAL_KEYS = _FORBIDDEN_APPROVAL_KEYS | frozenset({
    "assessment", "scenario_results", "findings", "finding", "observations", "private",
    "response", "request", "body", "evidence", "evidence_refs",
})
_FORBIDDEN_FINDINGS_KEYS = _FORBIDDEN_APPROVAL_KEYS | frozenset({
    "assessment", "private", "response", "request", "body", "evidence",
})


class ContractError(ValueError):
    """Raised when a contract is not canonical, bounded, or safe to disclose."""


def _fail(reason: str) -> None:
    # Reasons are stable categories, never values from untrusted records.
    raise ContractError(reason)


def _no_constant(_: str) -> None:
    _fail("non-finite JSON number")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _normalize(value: Any, depth: int = 0) -> Any:
    if depth > 16:
        _fail("maximum nesting depth exceeded")
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, float):
        _fail("non-portable JSON scalar")
    if isinstance(value, int):
        if not 0 <= value <= _SAFE_INT:
            _fail("integer outside portable range")
        return value
    if isinstance(value, str):
        if any(unicodedata.category(char) == "Cc" or 0xD800 <= ord(char) <= 0xDFFF
               for char in value):
            _fail("invalid text")
        normalized = unicodedata.normalize("NFC", value)
        if len(normalized.encode("utf-8")) > 4096:
            _fail("string length exceeded")
        return normalized
    if isinstance(value, list):
        return [_normalize(item, depth + 1) for item in value]
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("non-string object key")
            normalized_key = _normalize(key, depth + 1)
            if normalized_key in output:
                _fail("normalization-induced duplicate key")
            output[normalized_key] = _normalize(item, depth + 1)
        return output
    _fail("unsupported value type")


def parse_json(raw: bytes, *, max_bytes: int) -> Any:
    """Parse bounded UTF-8 JSON while preserving no ambiguous representation."""
    if not isinstance(raw, bytes) or isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        _fail("invalid parser input")
    if len(raw) > max_bytes:
        _fail("input exceeds size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid UTF-8")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant,
                           parse_float=lambda _: _fail("floating point is forbidden"))
    except ContractError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        _fail("invalid JSON")
    return _normalize(value)


def canonical_bytes(value: Any) -> bytes:
    try:
        normalized = _normalize(value)
        return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        _fail("not canonical JSON")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _object(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("object required")
    result = dict(value)
    if set(result) != fields:
        _fail("invalid v1 fields")
    return result


def _string(value: Any, *, limit: int = 4096, identifier: bool = False) -> str:
    if not isinstance(value, str):
        _fail("string required")
    if len(value.encode("utf-8")) > (128 if identifier else limit):
        _fail("string length exceeded")
    if not value:
        _fail("empty string")
    return value


def _integer(value: Any, *, lower: int = 0, upper: int = _SAFE_INT) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        _fail("integer outside permitted range")
    return value


def _enum(value: Any, choices: set[str]) -> str:
    value = _string(value)
    if value not in choices:
        _fail("invalid enum")
    return value


def _hash(value: Any) -> str:
    value = _string(value, identifier=True)
    if not _SHA256.fullmatch(value):
        _fail("invalid SHA-256 digest")
    return value


def _base64(value: Any, expected_bytes: int | None = None) -> str:
    value = _string(value, identifier=True)
    # decode then re-encode so non-canonical alternate padding/alphabet is rejected.
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError):
        _fail("invalid base64")
    if base64.b64encode(decoded).decode("ascii") != value:
        _fail("non-canonical base64")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        _fail("invalid base64 length")
    return value


def _list(value: Any, *, maximum: int, sorted_unique: bool = False) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _fail("invalid list")
    if sorted_unique:
        try:
            if value != sorted(value) or len(set(value)) != len(value):
                _fail("list must be sorted and unique")
        except TypeError:
            _fail("invalid list")
    return value


def _ordered_records(records: list[Any], key_fields: tuple[str, ...], *, semantic_field: str) -> None:
    """Require stable record order and one record for each semantic binding."""
    keys: list[tuple[Any, ...]] = []
    semantic: set[Any] = set()
    for record in records:
        if not isinstance(record, Mapping):
            _fail("invalid record ordering")
        try:
            key = tuple(record[field] for field in key_fields)
            identity = record[semantic_field]
        except KeyError:
            _fail("invalid record ordering")
        keys.append(key)
        if identity in semantic:
            _fail("duplicate semantic record")
        semantic.add(identity)
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        _fail("records must be sorted and unique")


def _id_fields(obj: Mapping[str, Any], fields: tuple[str, ...]) -> None:
    for field in fields:
        _string(obj[field], identifier=True)


def _environment(value: Any) -> dict[str, Any]:
    obj = _object(value, {"environment_id", "verification_record_digest", "origin", "environment_class"})
    _id_fields(obj, ("environment_id",))
    _hash(obj["verification_record_digest"])
    _enum(obj["environment_class"], {"staging", "sandbox"})
    origin = _string(obj["origin"], limit=1024)
    match = re.fullmatch(r"https://([a-z0-9.-]+)", origin)
    if not match or origin != origin.lower() or not _valid_hostname(match.group(1)):
        _fail("unsafe origin")
    return obj


def _valid_hostname(hostname: str) -> bool:
    if not _DNS.fullmatch(hostname) or hostname.startswith("-"):
        return False
    lowered = hostname.lower()
    # HTTPS canary targets must resolve through ordinary public DNS.  Local and
    # special-use names are never a safe assertion target, even if DNS happens to
    # resolve them in one environment.
    forbidden = (
        "localhost", ".localhost", ".local", ".internal", ".invalid",
        ".test", ".example", ".onion", ".home.arpa",
    )
    return not any(lowered == suffix or lowered.endswith(suffix) for suffix in forbidden)


def _route(value: Any) -> str:
    route = _string(value, limit=1024)
    if not _ROUTE.fullmatch(route) or "?" in route or "#" in route or "//" in route:
        _fail("unsafe route")
    return route


def _method(value: Any) -> str:
    return _enum(value, {"GET", "HEAD"})


def _scenario(value: Any, ordinal: int) -> dict[str, Any]:
    obj = _object(value, {"ordinal", "scenario_id", "adapter_version"})
    if _integer(obj["ordinal"]) != ordinal:
        _fail("non-contiguous ordinal")
    _id_fields(obj, ("scenario_id", "adapter_version"))
    return obj


def _scenarios(value: Any) -> list[dict[str, Any]]:
    entries = _list(value, maximum=4)
    seen = set()
    for ordinal, item in enumerate(entries):
        item = _scenario(item, ordinal)
        if item["scenario_id"] in seen:
            _fail("duplicate scenario")
        seen.add(item["scenario_id"])
    return entries


def _body_shapes(value: Any) -> list[str]:
    entries = _list(value, maximum=20, sorted_unique=True)
    for item in entries:
        _enum(item, {"absent", "empty", "json_object", "json_array", "json_scalar", "text", "binary", "truncated", "invalid"})
    return entries


def _statuses(value: Any) -> list[int]:
    entries = _list(value, maximum=20, sorted_unique=True)
    for item in entries:
        _integer(item, lower=100, upper=599)
    return entries


def _budgets(value: Any) -> dict[str, Any]:
    obj = _object(value, {"maximum_requests", "maximum_concurrency", "action_timeout_ms", "wall_timeout_ms", "maximum_response_bytes"})
    _integer(obj["maximum_requests"], lower=1, upper=20)
    if _integer(obj["maximum_concurrency"], lower=1, upper=1) != 1:
        _fail("concurrency must be one")
    _integer(obj["action_timeout_ms"], lower=1, upper=5000)
    _integer(obj["wall_timeout_ms"], lower=1, upper=60000)
    _integer(obj["maximum_response_bytes"], lower=1, upper=256 * 1024)
    return obj


def _egress(value: Any, environment: Mapping[str, Any]) -> dict[str, Any]:
    obj = _object(value, {"hostname", "port", "redirect_policy"})
    host = _string(obj["hostname"], identifier=True)
    if host != host.lower() or not _valid_hostname(host):
        _fail("unsafe egress host")
    if host != environment["origin"][8:]:
        _fail("egress host does not match origin")
    if _integer(obj["port"], lower=443, upper=443) != 443:
        _fail("invalid egress port")
    _enum(obj["redirect_policy"], {"deny"})
    return obj


def _retry(value: Any) -> dict[str, Any]:
    obj = _object(value, {"maximum_retries", "retryable_failure_codes"})
    _integer(obj["maximum_retries"], lower=0, upper=1)
    codes = _list(obj["retryable_failure_codes"], maximum=2, sorted_unique=True)
    for code in codes:
        _enum(code, {"connect_error", "timeout"})
    return obj


def _signature(obj: Mapping[str, Any], digest_field: str) -> None:
    _hash(obj[digest_field])
    _string(obj["signing_key_id"], identifier=True)
    _base64(obj["signature_b64"], 64)
    expected = canonical_digest({key: value for key, value in obj.items()
                                 if key not in {digest_field, "signing_key_id", "signature_b64"}})
    if obj[digest_field] != expected:
        _fail("digest mismatch")


def _reject_keys(value: Any, forbidden: frozenset[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in forbidden:
                _fail("forbidden private field")
            _reject_keys(item, forbidden)
    elif isinstance(value, list):
        for item in value:
            _reject_keys(item, forbidden)


def _contract(value: Any, maximum_bytes: int) -> Any:
    """Normalize a programmatic record and enforce its canonical transport ceiling."""
    result = _normalize(value)
    if len(canonical_bytes(result)) > maximum_bytes:
        _fail("contract exceeds size limit")
    return result


def validate_test_manifest(value: Any) -> dict[str, Any]:
    obj = _contract(value, 256 * 1024)
    obj = _object(obj, {"schema_version", "workspace_id", "project_id", "environment", "runner", "compiler", "scenarios", "actions", "credential_bindings", "budgets", "egress", "retry_policy", "local_evidence_policy", "compiled_at_ms", "manifest_digest"})
    _enum(obj["schema_version"], {TEST_MANIFEST_SCHEMA}); _id_fields(obj, ("workspace_id", "project_id"))
    env = _environment(obj["environment"])
    runner = _object(obj["runner"], {"runner_id", "runner_key_id", "minimum_runner_version"}); _id_fields(runner, ("runner_id", "runner_key_id", "minimum_runner_version"))
    compiler = _object(obj["compiler"], {"compiler_version", "engine_version"}); _id_fields(compiler, ("compiler_version", "engine_version"))
    scenarios = _scenarios(obj["scenarios"]); scenario_ids = {(x["scenario_id"], x["adapter_version"]) for x in scenarios}
    actions = _list(obj["actions"], maximum=20)
    for ordinal, action in enumerate(actions):
        action = _object(action, {"ordinal", "scenario_id", "adapter_version", "method", "route_template", "fixture_bindings", "semantic_auth_role", "auth_profile", "assertion_class", "allowed_status_codes", "allowed_body_shapes", "side_effect_class"})
        if _integer(action["ordinal"]) != ordinal: _fail("non-contiguous ordinal")
        _id_fields(action, ("scenario_id", "adapter_version", "semantic_auth_role"))
        if (action["scenario_id"], action["adapter_version"]) not in scenario_ids: _fail("unknown action scenario")
        _method(action["method"]); _route(action["route_template"])
        bindings = _list(action["fixture_bindings"], maximum=20)
        for binding in bindings:
            binding = _object(binding, {"parameter_name", "fixture_id"}); _id_fields(binding, ("parameter_name", "fixture_id"))
        _ordered_records(bindings, ("parameter_name", "fixture_id"), semantic_field="parameter_name")
        _enum(action["auth_profile"], {"anonymous", "bearer", "cookie_jar", "x_api_key"}); _enum(action["assertion_class"], {"anonymous_authenticated", "object_ownership", "role_boundary", "plan_entitlement"}); _statuses(action["allowed_status_codes"]); _body_shapes(action["allowed_body_shapes"]); _enum(action["side_effect_class"], {"read_only"})
    credentials = _list(obj["credential_bindings"], maximum=20)
    for binding in credentials:
        binding = _object(binding, {"semantic_role", "credential_handle_id", "auth_profile"}); _id_fields(binding, ("semantic_role",))
        if not isinstance(binding["credential_handle_id"], str) or not _HEX32.fullmatch(binding["credential_handle_id"]): _fail("invalid credential binding")
        _enum(binding["auth_profile"], {"anonymous", "bearer", "cookie_jar", "x_api_key"})
    _ordered_records(credentials, ("semantic_role", "auth_profile", "credential_handle_id"), semantic_field="semantic_role")
    _budgets(obj["budgets"]); _egress(obj["egress"], env); _retry(obj["retry_policy"])
    policy = _object(obj["local_evidence_policy"], {"retention_seconds"}); _integer(policy["retention_seconds"], lower=1)
    _integer(obj["compiled_at_ms"], lower=0); _hash(obj["manifest_digest"])
    if obj["manifest_digest"] != canonical_digest({k: v for k, v in obj.items() if k != "manifest_digest"}): _fail("digest mismatch")
    return copy.deepcopy(obj)


def validate_approval_projection(value: Any) -> dict[str, Any]:
    obj = _contract(value, 64 * 1024); _reject_keys(obj, _FORBIDDEN_APPROVAL_KEYS)
    # v2 is v1 plus exactly one closed, signed ``plan`` object; v1 can never carry one.
    v2 = isinstance(obj, Mapping) and obj.get("schema_version") == APPROVAL_PROJECTION_V2_SCHEMA
    if v2: _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "projection_id", "workspace_id", "project_id", "environment", "runner", "compiler", "scenarios", "actions", "budgets", "egress", "retry_policy", "compiled_at_ms", "manifest_digest", "projection_digest", "signing_key_id", "signature_b64"} | ({"plan"} if v2 else set()))
    _enum(obj["schema_version"], {APPROVAL_PROJECTION_SCHEMA, APPROVAL_PROJECTION_V2_SCHEMA}); _id_fields(obj, ("projection_id", "workspace_id", "project_id")); env = _environment(obj["environment"])
    runner = _object(obj["runner"], {"runner_id", "runner_key_id", "runner_version", "adapter_versions"}); _id_fields(runner, ("runner_id", "runner_key_id", "runner_version")); _version_list(runner["adapter_versions"])
    compiler = _object(obj["compiler"], {"compiler_version", "engine_version"}); _id_fields(compiler, ("compiler_version", "engine_version"))
    scenarios = _scenarios(obj["scenarios"]); scenario_ids = {(x["scenario_id"], x["adapter_version"]) for x in scenarios}
    actions = _list(obj["actions"], maximum=20)
    for ordinal, action in enumerate(actions):
        action = _object(action, {"ordinal", "scenario_id", "adapter_version", "method", "route_template", "semantic_auth_role", "assertion_class", "allowed_status_codes", "allowed_body_shapes", "side_effect_class"})
        if _integer(action["ordinal"]) != ordinal: _fail("invalid action ordering")
        _id_fields(action, ("scenario_id", "adapter_version", "semantic_auth_role"))
        if (action["scenario_id"], action["adapter_version"]) not in scenario_ids: _fail("invalid action ordering")
        _method(action["method"]); _route(action["route_template"]); _enum(action["assertion_class"], {"anonymous_authenticated", "object_ownership", "role_boundary", "plan_entitlement"}); _statuses(action["allowed_status_codes"]); _body_shapes(action["allowed_body_shapes"]); _enum(action["side_effect_class"], {"read_only"})
    _budgets(obj["budgets"]); _egress(obj["egress"], env); _retry(obj["retry_policy"]); _integer(obj["compiled_at_ms"], lower=0); _hash(obj["manifest_digest"])
    if obj["signing_key_id"] != runner["runner_key_id"]: _fail("approval signing key mismatch")
    if v2: _plan(obj["plan"], actions, obj["budgets"])
    _signature(obj, "projection_digest")
    return copy.deepcopy(obj)


def validate_runner_context_binding(value: Any) -> dict[str, Any]:
    """Validate the closed, cloud-signed authorization artifact.

    Cryptographic verification belongs to the cloud/runner trust boundary; this pure
    contract checker establishes the canonical unsigned bytes that both sides verify.
    """
    obj = _contract(value, 16 * 1024)
    obj = _object(obj, {
        "schema_version", "binding_id", "workspace_id", "project_id", "environment",
        "runner_binding", "authorization", "issued_at_ms", "expires_at_ms",
        "binding_digest", "signing_key_id", "signature_b64",
    })
    _enum(obj["schema_version"], {RUNNER_CONTEXT_BINDING_SCHEMA})
    if not isinstance(obj["binding_id"], str) or not re.fullmatch(r"rcb_[0-9a-f]{32}", obj["binding_id"]):
        _fail("invalid context binding id")
    _id_fields(obj, ("workspace_id", "project_id", "signing_key_id"))
    _environment(obj["environment"])
    runner = _object(obj["runner_binding"], {"runner_id", "runner_key_id", "public_key_digest"})
    _id_fields(runner, ("runner_id", "runner_key_id")); _hash(runner["public_key_digest"])
    authorization = _object(obj["authorization"], {"user_id", "role"})
    _id_fields(authorization, ("user_id",)); _enum(authorization["role"], {"owner", "admin"})
    issued = _integer(obj["issued_at_ms"], lower=0)
    expires = _integer(obj["expires_at_ms"], lower=0)
    if not issued < expires <= issued + 86_400_000:
        _fail("invalid context binding expiry")
    unsigned = {
        key: obj[key] for key in (
            "schema_version", "binding_id", "workspace_id", "project_id", "environment", "runner_binding",
            "authorization", "issued_at_ms", "expires_at_ms",
        )
    }
    _hash(obj["binding_digest"])
    if obj["binding_digest"] != canonical_digest(unsigned):
        _fail("digest mismatch")
    _base64(obj["signature_b64"], 64)
    return copy.deepcopy(obj)


def validate_runner_context_create(value: Any) -> dict[str, Any]:
    obj = _contract(value, 2 * 1024)
    obj = _object(obj, {
        "schema_version", "environment_id", "verification_record_digest", "runner_id",
        "runner_key_id",
    })
    _enum(obj["schema_version"], {RUNNER_CONTEXT_BINDING_CREATE_SCHEMA})
    _id_fields(obj, ("environment_id", "runner_id", "runner_key_id"))
    _hash(obj["verification_record_digest"])
    return copy.deepcopy(obj)


def validate_runner_context_revoke(value: Any) -> dict[str, Any]:
    obj = _contract(value, 256)
    obj = _object(obj, {"schema_version", "reason_code"})
    _enum(obj["schema_version"], {RUNNER_CONTEXT_BINDING_REVOKE_SCHEMA})
    _enum(obj["reason_code"], {"operator_requested"})
    return copy.deepcopy(obj)


def validate_runner_context_list(value: Any) -> dict[str, Any]:
    obj = _contract(value, 128)
    obj = _object(obj, {"schema_version"})
    _enum(obj["schema_version"], {RUNNER_CONTEXT_LIST_SCHEMA})
    return copy.deepcopy(obj)


def validate_runner_context_claim(value: Any) -> dict[str, Any]:
    obj = _contract(value, 256)
    obj = _object(obj, {"schema_version", "binding_id", "binding_digest"})
    _enum(obj["schema_version"], {RUNNER_CONTEXT_CLAIM_SCHEMA})
    if not isinstance(obj["binding_id"], str) or not re.fullmatch(r"rcb_[0-9a-f]{32}", obj["binding_id"]):
        _fail("invalid context binding id")
    _hash(obj["binding_digest"])
    return copy.deepcopy(obj)


def validate_runner_approval_projection_submit(value: Any) -> dict[str, Any]:
    obj = _contract(value, 69632)
    obj = _object(obj, {"schema_version", "context_binding_id", "context_binding_digest", "approval_projection"})
    _enum(obj["schema_version"], {RUNNER_APPROVAL_PROJECTION_SUBMIT_SCHEMA})
    if not isinstance(obj["context_binding_id"], str) or not re.fullmatch(r"rcb_[0-9a-f]{32}", obj["context_binding_id"]):
        _fail("invalid context binding id")
    _hash(obj["context_binding_digest"])
    obj["approval_projection"] = validate_approval_projection(obj["approval_projection"])
    if len(canonical_bytes(obj["approval_projection"])) > 65536:
        _fail("approval projection exceeds size limit")
    return copy.deepcopy(obj)


def _version_list(value: Any) -> list[str]:
    items = _list(value, maximum=20, sorted_unique=True)
    for item in items: _string(item, identifier=True)
    return items


def validate_runner_identity(value: Any) -> dict[str, Any]:
    obj = _contract(value, 16 * 1024); obj = _object(obj, {"schema_version", "runner_id", "workspace_id", "public_key", "fingerprint", "runner_version", "adapter_versions", "capabilities", "pairing", "last_heartbeat_at_ms", "state", "rotation", "revocation", "identity_digest"})
    _enum(obj["schema_version"], {RUNNER_IDENTITY_SCHEMA}); _id_fields(obj, ("runner_id", "workspace_id", "runner_version")); key = _object(obj["public_key"], {"algorithm", "key_id", "public_key_b64"}); _enum(key["algorithm"], {"Ed25519"}); _id_fields(key, ("key_id",)); _base64(key["public_key_b64"], 32); _hash(obj["fingerprint"]); _version_list(obj["adapter_versions"])
    if obj["capabilities"] != ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"]: _fail("invalid runner capabilities")
    pairing = _object(obj["pairing"], {"paired_by", "paired_at_ms", "fingerprint_confirmation", "phrase_confirmation"}); _id_fields(pairing, ("paired_by",)); _integer(pairing["paired_at_ms"], lower=0); _enum(pairing["fingerprint_confirmation"], {"confirmed"}); _enum(pairing["phrase_confirmation"], {"confirmed"}); _integer(obj["last_heartbeat_at_ms"], lower=0)
    state = _enum(obj["state"], {"active", "rotating", "revoked", "replaced"}); rotation = _object(obj["rotation"], {"previous_key_ids", "rotated_at_ms", "verification_overlap_ends_at_ms"}); keys = _list(rotation["previous_key_ids"], maximum=20, sorted_unique=True)
    for item in keys: _string(item, identifier=True)
    for name in ("rotated_at_ms", "verification_overlap_ends_at_ms"):
        if rotation[name] is not None: _integer(rotation[name], lower=0)
    revocation = _object(obj["revocation"], {"revoked_at_ms", "revoked_by", "reason_code"})
    present = [revocation[x] is not None for x in revocation]
    if any(present) and not all(present): _fail("inconsistent revocation")
    if state == "active" and any(present): _fail("active runner revoked")
    if state in {"revoked", "replaced"} and not all(present): _fail("revocation required")
    if revocation["revoked_at_ms"] is not None: _integer(revocation["revoked_at_ms"], lower=0); _id_fields(revocation, ("revoked_by", "reason_code"))
    _hash(obj["identity_digest"])
    if obj["identity_digest"] != canonical_digest({k:v for k,v in obj.items() if k != "identity_digest"}): _fail("digest mismatch")
    return copy.deepcopy(obj)


def validate_execution_grant(value: Any) -> dict[str, Any]:
    obj = _contract(value, 32 * 1024); obj = _object(obj, {"schema_version", "grant_id", "run_id", "workspace_id", "project_id", "approval", "environment", "runner_binding", "approval_actor", "approval_reason", "consented_at_ms", "budgets", "egress", "retry_policy", "grant_nonce", "kill_switch_generation", "operational_receipt_policy", "issued_at_ms", "expires_at_ms", "grant_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {EXECUTION_GRANT_SCHEMA}); _id_fields(obj, ("grant_id", "run_id", "workspace_id", "project_id", "grant_nonce")); approval = _object(obj["approval"], {"projection_id", "projection_digest", "manifest_digest"}); _id_fields(approval, ("projection_id",)); _hash(approval["projection_digest"]); _hash(approval["manifest_digest"]); env = _environment(obj["environment"])
    binding = _object(obj["runner_binding"], {"runner_id", "runner_key_id", "public_key_digest"}); _id_fields(binding, ("runner_id", "runner_key_id")); _hash(binding["public_key_digest"]); actor = _object(obj["approval_actor"], {"user_id", "role"}); _id_fields(actor, ("user_id",)); _enum(actor["role"], {"owner", "admin"}); _string(obj["approval_reason"], limit=500); _integer(obj["consented_at_ms"], lower=0); _budgets(obj["budgets"]); _egress(obj["egress"], env); _retry(obj["retry_policy"]); _integer(obj["kill_switch_generation"], lower=0)
    policy = _object(obj["operational_receipt_policy"], {"schema_version", "maximum_bytes", "allowed_error_categories", "allowed_stop_reasons", "allowed_containment_codes"}); _enum(policy["schema_version"], {OPERATIONAL_RUN_SCHEMA}); _integer(policy["maximum_bytes"], lower=1, upper=32768); _enum_list(policy["allowed_error_categories"], _ERRORS); _enum_list(policy["allowed_stop_reasons"], _STOPS); _enum_list(policy["allowed_containment_codes"], _CONTAINMENT)
    issued = _integer(obj["issued_at_ms"], lower=0); expires = _integer(obj["expires_at_ms"], lower=0)
    if not issued < expires <= issued + 600000: _fail("invalid grant expiry")
    _signature(obj, "grant_digest"); return copy.deepcopy(obj)


_ERRORS = {"none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired", "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted", "containment_rejected", "cloud_disconnected"}
_STOPS = {"none", "local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch"}
_CONTAINMENT = {"admitted", "action_started", "action_completed", "action_rejected", "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted"}


def _enum_list(value: Any, choices: set[str], maximum: int = 20) -> list[str]:
    values = _list(value, maximum=maximum, sorted_unique=True)
    for item in values: _enum(item, choices)
    return values


def validate_operational_run(value: Any) -> dict[str, Any]:
    obj = _contract(value, 32 * 1024); _reject_keys(obj, _FORBIDDEN_OPERATIONAL_KEYS); obj = _object(obj, {"schema_version", "run_id", "grant_id", "workspace_id", "project_id", "manifest_digest", "approval_projection_digest", "grant_digest", "event_sequence", "lifecycle_phase", "execution_disposition", "timestamps", "counters", "versions", "error_category", "stop_reason", "containment_codes", "redaction_count", "projection_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {OPERATIONAL_RUN_SCHEMA}); _id_fields(obj, ("run_id", "grant_id", "workspace_id", "project_id")); _hash(obj["manifest_digest"]); _hash(obj["approval_projection_digest"]); _hash(obj["grant_digest"]); _integer(obj["event_sequence"], lower=0); phase = _enum(obj["lifecycle_phase"], {"prepared", "awaiting_execution_approval", "approved", "claimed", "running", "stop_requested", "finalizing", "terminal", "cancelled", "expired"})
    terminal = phase == "terminal"; disposition = obj["execution_disposition"]
    if terminal:
        _enum(disposition, {"completed", "incomplete", "failed", "stopped"})
    elif disposition is not None: _fail("preterminal disposition")
    timestamps = _object(obj["timestamps"], {"claimed_at_ms", "started_at_ms", "updated_at_ms", "stop_requested_at_ms", "stop_acknowledged_at_ms", "terminal_at_ms"})
    for field, moment in timestamps.items():
        if moment is not None: _integer(moment, lower=0)
    if terminal != (timestamps["terminal_at_ms"] is not None): _fail("terminal timestamp consistency")
    claimed = timestamps["claimed_at_ms"]; started = timestamps["started_at_ms"]
    stop_requested = timestamps["stop_requested_at_ms"]; stop_acknowledged = timestamps["stop_acknowledged_at_ms"]
    updated = _integer(timestamps["updated_at_ms"], lower=0); terminal_at = timestamps["terminal_at_ms"]
    if started is not None and (claimed is None or claimed > started): _fail("invalid claim/start ordering")
    if stop_acknowledged is not None and (stop_requested is None or stop_requested > stop_acknowledged): _fail("invalid stop ordering")
    if terminal_at is not None:
        for moment in (claimed, started, stop_requested, stop_acknowledged):
            if moment is not None and moment > terminal_at: _fail("invalid terminal ordering")
    if any(moment is not None and moment > updated for moment in (claimed, started, stop_requested, stop_acknowledged, terminal_at)):
        _fail("updated timestamp precedes event")
    if phase in {"prepared", "awaiting_execution_approval", "approved"} and any(
        moment is not None for moment in (claimed, started, stop_requested, stop_acknowledged)
    ): _fail("invalid pre-claim timestamps")
    if phase == "claimed" and (claimed is None or started is not None or stop_requested is not None or stop_acknowledged is not None): _fail("invalid claimed timestamps")
    if phase == "running" and (claimed is None or started is None or stop_requested is not None or stop_acknowledged is not None): _fail("invalid running timestamps")
    if phase == "stop_requested" and (claimed is None or started is None or stop_requested is None): _fail("invalid stop-request timestamps")
    if phase == "finalizing" and (claimed is None or started is None): _fail("invalid finalizing timestamps")
    if phase == "terminal" and (claimed is None or started is None): _fail("invalid terminal timestamps")
    if phase in {"cancelled", "expired"} and any(
        moment is not None for moment in (claimed, started, stop_requested, stop_acknowledged, terminal_at)
    ): _fail("invalid pre-claim terminal timestamps")
    counters = _object(obj["counters"], {"requests_started", "requests_completed", "response_bytes_read", "actions_contained", "retries_used", "remaining_requests", "remaining_wall_ms"})
    for number in counters.values(): _integer(number, lower=0)
    if counters["requests_started"] > 20 or counters["requests_completed"] > counters["requests_started"] or counters["actions_contained"] > counters["requests_started"] or counters["actions_contained"] > 20 or counters["retries_used"] > 1 or counters["remaining_requests"] > 20 or counters["requests_started"] + counters["remaining_requests"] > 20 or counters["remaining_wall_ms"] > 60000:
        _fail("operational counter ceiling")
    versions = _object(obj["versions"], {"runner_version", "engine_version", "adapter_versions"}); _id_fields(versions, ("runner_version", "engine_version")); _version_list(versions["adapter_versions"]); _enum(obj["error_category"], _ERRORS); _enum(obj["stop_reason"], _STOPS); _enum_list(obj["containment_codes"], _CONTAINMENT); _integer(obj["redaction_count"], lower=0); _signature(obj, "projection_digest"); return copy.deepcopy(obj)


def validate_runner_claim_request(value: Any) -> dict[str, Any]:
    """Validate the one closed, bodyless runner-claim request envelope."""
    obj = _contract(value, 256)
    obj = _object(obj, {"schema_version"})
    _enum(obj["schema_version"], {RUNNER_CLAIM_REQUEST_SCHEMA})
    return copy.deepcopy(obj)


def _runner_operation_request(value: Any, *, schema: str, phases: set[str], stop_ack: bool = False) -> dict[str, Any]:
    # 36 KiB is the transport ceiling.  The nested operational projection remains
    # independently frozen at 32 KiB by validate_operational_run.
    obj = _contract(value, 36 * 1024)
    obj = _object(obj, {"schema_version", "run_id", "operational_projection"})
    _enum(obj["schema_version"], {schema})
    _id_fields(obj, ("run_id",))
    projection = validate_operational_run(obj["operational_projection"])
    if projection["run_id"] != obj["run_id"]:
        _fail("runner request run ID mismatch")
    if projection["lifecycle_phase"] not in phases:
        _fail("invalid runner request lifecycle")
    if stop_ack:
        if projection["timestamps"]["stop_acknowledged_at_ms"] is None:
            _fail("stop acknowledgement timestamp required")
        if projection["stop_reason"] == "none":
            _fail("stop acknowledgement reason required")
    obj["operational_projection"] = projection
    return copy.deepcopy(obj)


def validate_runner_heartbeat_request(value: Any) -> dict[str, Any]:
    return _runner_operation_request(value, schema=RUNNER_HEARTBEAT_REQUEST_SCHEMA,
                                     phases={"claimed", "running", "stop_requested", "finalizing"})


def validate_runner_progress_request(value: Any) -> dict[str, Any]:
    return _runner_operation_request(value, schema=RUNNER_PROGRESS_REQUEST_SCHEMA,
                                     phases={"claimed", "running", "stop_requested", "finalizing"})


def validate_runner_result_request(value: Any) -> dict[str, Any]:
    # A discovery round's signed candidate report rides on its terminal result (contract §2.6).
    if isinstance(value, Mapping) and "discovery_round_report" in value:
        report = validate_discovery_round_report(value["discovery_round_report"])
        request = _runner_operation_request(
            {key: item for key, item in value.items() if key != "discovery_round_report"},
            schema=RUNNER_RESULT_REQUEST_SCHEMA, phases={"terminal"},
        )
        if report["run_id"] != request["run_id"] or report["grant_id"] != request["operational_projection"]["grant_id"]:
            _fail("discovery report run mismatch")
        request["discovery_round_report"] = report
        return request
    return _runner_operation_request(value, schema=RUNNER_RESULT_REQUEST_SCHEMA,
                                     phases={"terminal"})


def validate_runner_stop_ack_request(value: Any) -> dict[str, Any]:
    return _runner_operation_request(value, schema=RUNNER_STOP_ACK_REQUEST_SCHEMA,
                                     phases={"stop_requested", "finalizing", "terminal"}, stop_ack=True)


def validate_canary_findings(value: Any) -> dict[str, Any]:
    obj = _contract(value, 256 * 1024); _reject_keys(obj, _FORBIDDEN_FINDINGS_KEYS); obj = _object(obj, {"schema_version", "projection_id", "run_id", "grant_id", "workspace_id", "project_id", "environment_id", "manifest_digest", "approval_projection_digest", "grant_digest", "engine_version", "adapter_versions", "started_at_ms", "finished_at_ms", "assessment_outcome", "scenario_results", "containment_codes", "redaction_count", "projection_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {CANARY_FINDINGS_SCHEMA}); _id_fields(obj, ("projection_id", "run_id", "grant_id", "workspace_id", "project_id", "environment_id", "engine_version")); _hash(obj["manifest_digest"]); _hash(obj["approval_projection_digest"]); _hash(obj["grant_digest"]); _version_list(obj["adapter_versions"]); start = _integer(obj["started_at_ms"], lower=0); finish = _integer(obj["finished_at_ms"], lower=0)
    if finish < start: _fail("invalid findings timestamps")
    _enum(obj["assessment_outcome"], {"blocked", "observed", "inconclusive"}); entries = _list(obj["scenario_results"], maximum=4); seen = set(); total_observations = 0
    for ordinal, item in enumerate(entries):
        item = _object(item, {"ordinal", "scenario_id", "adapter_version", "assessment_outcome", "route", "observations", "finding", "containment_codes", "redaction_count", "local_evidence_refs"})
        if _integer(item["ordinal"]) != ordinal: _fail("non-contiguous ordinal")
        _id_fields(item, ("scenario_id", "adapter_version"))
        if item["scenario_id"] in seen: _fail("duplicate scenario result")
        seen.add(item["scenario_id"]); _enum(item["assessment_outcome"], {"blocked", "observed", "inconclusive"}); route = _object(item["route"], {"method", "route_template"}); _method(route["method"]); _route(route["route_template"])
        observations = _list(item["observations"], maximum=20)
        for observation in observations:
            observation = _object(observation, {"semantic_role", "status_code", "body_shape", "truncation_state"}); _id_fields(observation, ("semantic_role",)); _integer(observation["status_code"], lower=100, upper=599); _enum(observation["body_shape"], {"absent", "empty", "json_object", "json_array", "json_scalar", "text", "binary", "truncated", "invalid"}); _enum(observation["truncation_state"], {"complete", "truncated"})
        _ordered_records(observations, ("semantic_role", "status_code", "body_shape", "truncation_state"), semantic_field="semantic_role")
        total_observations += len(observations)
        finding = item["finding"]
        if finding is not None:
            finding = _object(finding, {"title", "reachability_rationale", "confidence", "recommended_control", "regression_suggestion"}); _string(finding["title"], limit=160)
            for field in ("reachability_rationale", "recommended_control", "regression_suggestion"): _string(finding[field], limit=2000)
            _enum(finding["confidence"], {"low", "medium", "high"})
        _enum_list(item["containment_codes"], _CONTAINMENT); _integer(item["redaction_count"], lower=0); refs = _list(item["local_evidence_refs"], maximum=10, sorted_unique=True)
        for ref in refs:
            if not isinstance(ref, str) or not _EVIDENCE.fullmatch(ref): _fail("invalid evidence reference")
    if total_observations > 20: _fail("too many observations")
    _enum_list(obj["containment_codes"], _CONTAINMENT); _integer(obj["redaction_count"], lower=0); _signature(obj, "projection_digest"); return copy.deepcopy(obj)


def validate_disclosure_permit(value: Any) -> dict[str, Any]:
    obj = _contract(value, 16 * 1024); obj = _object(obj, {"schema_version", "permit_id", "workspace_id", "project_id", "run_id", "grant_id", "runner_binding", "projection", "approved_by", "approved_at_ms", "issued_at_ms", "expires_at_ms", "permit_nonce", "permit_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {DISCLOSURE_PERMIT_SCHEMA}); _id_fields(obj, ("permit_id", "workspace_id", "project_id", "run_id", "grant_id", "approved_by", "permit_nonce")); binding = _object(obj["runner_binding"], {"runner_id", "runner_key_id"}); _id_fields(binding, ("runner_id", "runner_key_id")); projection = _object(obj["projection"], {"schema_version", "projection_digest", "maximum_bytes", "scenario_count", "finding_count"}); _enum(projection["schema_version"], {CANARY_FINDINGS_SCHEMA}); _hash(projection["projection_digest"]); _integer(projection["maximum_bytes"], lower=1, upper=262144); _integer(projection["scenario_count"], lower=0, upper=4); _integer(projection["finding_count"], lower=0, upper=4); _integer(obj["approved_at_ms"], lower=0); issued = _integer(obj["issued_at_ms"], lower=0); expires = _integer(obj["expires_at_ms"], lower=0)
    if not issued < expires <= issued + 600000: _fail("invalid permit expiry")
    _signature(obj, "permit_digest"); return copy.deepcopy(obj)


# --- discovery authorization, v2 plan object, inventory provenance (C2 contract §2) ---

DISCOVERY_SEED_DIGEST = canonical_digest(list(DISCOVERY_SEED_PATHS))
_AUTHORIZATION_ID = re.compile(r"^dau_[0-9a-f]{32}$")
_PLAN_REQUEST_ID = re.compile(r"^cpr_[0-9a-f]{32}$")
_CONTEXT_BINDING_ID = re.compile(r"^rcb_[0-9a-f]{32}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_SEGMENT = re.compile(r"^[a-z0-9_-]{1,32}$")
_POSITIONAL = re.compile(r"^\{p([1-9][0-9]?)\}$")
_VALUE_SEGMENTS = (
    re.compile(r"^[0-9]+$"), re.compile(r"^[0-9a-f]{12,}$"),
    re.compile(r"(?:^|[_-])(?:sk|pk|rk)_(?:live|test)_"), re.compile(r"^(?:ghp|gho|ghs|ghu|xox[abpr])[_-]"),
)
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .-]{0,31}$")
_PRINTABLE_LABEL = re.compile(r"^[\x21-\x7e](?:[\x20-\x7e]{0,30}[\x21-\x7e])?$")
_PLAN_ROLES = ("higher_plan", "lower_plan")


def _entropy_bits(segment: str) -> float:
    counts = {character: segment.count(character) for character in set(segment)}
    total = len(segment)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _route_template(value: Any) -> str:
    """A projected template keeps only allowlisted vocabulary segments (launch spec §3.3).

    This is a conservative classifier, not a redactor: anything that could be a value
    (addresses, numbers, hex, tokens, mixed case, dots, high-entropy text) is refused, and the
    executor must have replaced it by a positional placeholder before projecting.
    """
    route = _route(value)
    if route in DISCOVERY_SEED_PATHS:
        return route
    expected = 1
    for segment in route[1:].split("/"):
        positional = _POSITIONAL.fullmatch(segment)
        if positional:
            if int(positional.group(1)) != expected:
                _fail("non-sequential route placeholder")
            expected += 1
            continue
        if not _SEGMENT.fullmatch(segment) or any(pattern.search(segment) for pattern in _VALUE_SEGMENTS):
            _fail("route segment is not template vocabulary")
        if len(segment) >= 16 and _entropy_bits(segment) >= 3.5:
            _fail("route segment is not template vocabulary")
    return route


def _plan_label(value: Any) -> str:
    label = _string(value, identifier=True)
    if not _LABEL.fullmatch(label) or re.fullmatch(r"[0-9a-fA-F]{16,}", label.replace("-", "")):
        _fail("invalid plan label")
    return label


def _plan_labels(value: Any, *, minimum: int) -> list[dict[str, Any]]:
    entries = _list(value, maximum=2)
    if len(entries) < minimum:
        _fail("invalid plan labels")
    roles = []
    for entry in entries:
        entry = _object(entry, {"role", "plan_label"})
        roles.append(_enum(entry["role"], set(_PLAN_ROLES)))
        _plan_label(entry["plan_label"])
    if roles != sorted(set(roles)):
        _fail("plan labels must be sorted and unique")
    return entries


def _plan(value: Any, actions: list[Any], budgets: Mapping[str, Any]) -> dict[str, Any]:
    kind = value.get("plan_kind") if isinstance(value, Mapping) else None
    if kind == "discovery":
        return _discovery_plan(value, actions, budgets)
    obj = _object(value, {
        "plan_kind", "plan_request_id", "plan_request_nonce", "inventory_digest", "selection_digest",
        "selected_count", "plan_labels", "max_ops", "not_executed_count", "not_executed_digest",
    })
    _enum(obj["plan_kind"], {"plan_differential", "regression"})
    if not isinstance(obj["plan_request_id"], str) or not _PLAN_REQUEST_ID.fullmatch(obj["plan_request_id"]):
        _fail("invalid plan request id")
    if not isinstance(obj["plan_request_nonce"], str) or not _NONCE.fullmatch(obj["plan_request_nonce"]):
        _fail("invalid plan request nonce")
    for field in ("inventory_digest", "selection_digest", "not_executed_digest"):
        _hash(obj[field])
    _integer(obj["selected_count"], lower=1, upper=10); _integer(obj["max_ops"], lower=1, upper=20)
    _integer(obj["not_executed_count"], lower=0, upper=10)
    _plan_labels(obj["plan_labels"], minimum=2)
    for action in actions:
        _route_template(action["route_template"])
    return obj


def _discovery_plan(value: Any, actions: list[Any], budgets: Mapping[str, Any]) -> dict[str, Any]:
    obj = _object(value, {
        "plan_kind", "authorization_id", "authorization_digest", "round", "frontier_digest",
        "cumulative_requests_before", "transport_profile", "action_count", "sources",
    })
    if not isinstance(obj["authorization_id"], str) or not _AUTHORIZATION_ID.fullmatch(obj["authorization_id"]):
        _fail("invalid discovery authorization id")
    _hash(obj["authorization_digest"]); _hash(obj["frontier_digest"])
    round_number = _integer(obj["round"], lower=1, upper=DISCOVERY_BOUND["max_rounds"])
    cumulative = _integer(obj["cumulative_requests_before"], lower=0, upper=DISCOVERY_BOUND["max_requests"] - 1)
    _enum(obj["transport_profile"], {"discovery"})
    count = _integer(obj["action_count"], lower=1, upper=DISCOVERY_BOUND["max_actions_per_round"])
    if count != len(actions) or budgets["maximum_requests"] != count:
        _fail("discovery action count mismatch")
    sources = _list(obj["sources"], maximum=DISCOVERY_BOUND["max_actions_per_round"])
    if len(sources) != count:
        _fail("discovery source count mismatch")
    for ordinal, source in enumerate(sources):
        source = _object(source, {"ordinal", "round", "source_ordinal"})
        if _integer(source["ordinal"]) != ordinal:
            _fail("non-contiguous discovery source")
        source_round = _integer(source["round"], lower=0, upper=round_number - 1)
        _integer(source["source_ordinal"], lower=0, upper=19)
        # Round 0 names the fixed seed list, which only round 1 may draw from.
        if (round_number == 1) != (source_round == 0):
            _fail("discovery source round mismatch")
    for action in actions:
        _route_template(action["route_template"])
    if round_number == 1:
        routes = [action["route_template"] for action in actions]
        if (
            cumulative != 0 or obj["frontier_digest"] != DISCOVERY_SEED_DIGEST
            or sorted(routes) != sorted(DISCOVERY_SEED_PATHS)
            or any(DISCOVERY_SEED_PATHS[source["source_ordinal"]] != route
                   for source, route in zip(sources, routes))
        ):
            _fail("discovery round one is not the seed list")
    return obj


def discovery_frontier_digest(referenced: list[Mapping[str, Any]]) -> str:
    """Digest of ``[{round, candidate}]`` exactly as stored, in the plan's source order."""
    return canonical_digest([{"round": item["round"], "candidate": item["candidate"]} for item in referenced])


def validate_discovery_authorization_request(value: Any) -> dict[str, Any]:
    # ``login_exchange_authorized`` is the one JSON boolean in C2; C5 owns ``true``.  It is
    # stored as integer 0 because canonical contract bytes never encode booleans.
    if not isinstance(value, Mapping) or value.get("login_exchange_authorized") is not False:
        _fail("login exchange authorization is not available")
    obj = _contract({**dict(value), "login_exchange_authorized": 0}, 2 * 1024)
    _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "environment_id", "identities_authorized", "login_exchange_authorized", "acknowledgement"})
    _enum(obj["schema_version"], {DISCOVERY_AUTHORIZATION_SCHEMA}); _id_fields(obj, ("environment_id",))
    identities = _list(obj["identities_authorized"], maximum=2)
    for identity in identities:
        if not isinstance(identity, str) or not _PRINTABLE_LABEL.fullmatch(identity):
            _fail("invalid identity label")
    if len(set(identities)) != len(identities):
        _fail("duplicate identity label")
    if obj["acknowledgement"] != DISCOVERY_ACKNOWLEDGEMENT:
        _fail("discovery acknowledgement mismatch")
    return copy.deepcopy(obj)


def _candidates(value: Any, *, kinds: frozenset[str]) -> list[dict[str, Any]]:
    entries = _list(value, maximum=200)
    seen = set()
    for entry in entries:
        entry = _object(entry, {"method", "route_template", "provenance_kind", "source_ordinal", "status_code"})
        key = (_method(entry["method"]), _route_template(entry["route_template"]))
        if key in seen:
            _fail("duplicate discovery candidate")
        seen.add(key)
        _enum(entry["provenance_kind"], set(kinds)); _integer(entry["source_ordinal"], lower=0, upper=19)
        _integer(entry["status_code"], lower=100, upper=599)
    return entries


def validate_discovery_round_report(value: Any) -> dict[str, Any]:
    obj = _contract(value, 64 * 1024); _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "authorization_id", "round", "run_id", "grant_id", "candidates", "excluded_count", "truncated_count", "bytes_received", "report_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {DISCOVERY_ROUND_REPORT_SCHEMA})
    if not isinstance(obj["authorization_id"], str) or not _AUTHORIZATION_ID.fullmatch(obj["authorization_id"]):
        _fail("invalid discovery authorization id")
    _integer(obj["round"], lower=1, upper=DISCOVERY_BOUND["max_rounds"]); _id_fields(obj, ("run_id", "grant_id"))
    _candidates(obj["candidates"], kinds=_ROUND_PROVENANCE_KINDS)
    _integer(obj["excluded_count"], lower=0, upper=10_000); _integer(obj["truncated_count"], lower=0, upper=10_000)
    _integer(obj["bytes_received"], lower=0, upper=DISCOVERY_BOUND["max_actions_per_round"] * DISCOVERY_BOUND["max_body_bytes"])
    _signature(obj, "report_digest")
    return copy.deepcopy(obj)


def validate_route_inventory_rows(value: Any) -> list[dict[str, Any]]:
    """Closed inventory rows: templates, provenance and state only, never values (§2.5)."""
    rows = _contract(value, 256 * 1024); _reject_keys(rows, _FORBIDDEN_DISCOVERY_KEYS)
    rows = _list(rows, maximum=200)
    seen = set()
    for row in rows:
        excluded = isinstance(row, Mapping) and row.get("state") == "excluded"
        row = _object(row, {"method", "route_template", "provenance", "first_seen_ms", "state"} | ({"excluded_reason"} if excluded else set()))
        key = (_method(row["method"]), _route_template(row["route_template"]))
        if key in seen:
            _fail("duplicate inventory route")
        seen.add(key)
        provenance = _list(row["provenance"], maximum=8)
        if not provenance:
            _fail("inventory provenance required")
        sources = set()
        for item in provenance:
            item = _object(item, {"kind", "round", "source_ordinal", "status_code"})
            _enum(item["kind"], set(DISCOVERY_PROVENANCE_KINDS)); _integer(item["round"], lower=0, upper=DISCOVERY_BOUND["max_rounds"])
            _integer(item["source_ordinal"], lower=0, upper=19)
            if item["status_code"] is not None:
                _integer(item["status_code"], lower=100, upper=599)
            source = (item["kind"], item["round"], item["source_ordinal"])
            if source in sources:
                _fail("duplicate inventory provenance")
            sources.add(source)
        _integer(row["first_seen_ms"], lower=0); _enum(row["state"], {"candidate", "selected", "excluded"})
        if excluded:
            _enum(row["excluded_reason"], set(DISCOVERY_EXCLUDED_REASONS))
    return copy.deepcopy(rows)


def _route_selection(value: Any, *, maximum: int) -> list[dict[str, Any]]:
    routes = _list(value, maximum=maximum)
    if not routes:
        _fail("route selection required")
    seen = set()
    for route in routes:
        route = _object(route, {"method", "route_template"})
        key = (_method(route["method"]), _route_template(route["route_template"]))
        if key in seen:
            _fail("duplicate selected route")
        seen.add(key)
    return routes


def validate_plan_request(value: Any) -> dict[str, Any]:
    obj = _contract(value, 2 * 1024); _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "plan_kind", "max_ops", "routes"})
    _enum(obj["schema_version"], {PLAN_REQUEST_SCHEMA}); _enum(obj["plan_kind"], {"plan_differential"})
    _integer(obj["max_ops"], lower=1, upper=20); _route_selection(obj["routes"], maximum=10)
    return copy.deepcopy(obj)


def validate_runner_plan_request_claim(value: Any) -> dict[str, Any]:
    obj = _contract(value, 2 * 1024); _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "binding_id", "binding_digest", "credential_roles"})
    _enum(obj["schema_version"], {RUNNER_PLAN_REQUEST_CLAIM_SCHEMA})
    if not isinstance(obj["binding_id"], str) or not _CONTEXT_BINDING_ID.fullmatch(obj["binding_id"]):
        _fail("invalid context binding id")
    _hash(obj["binding_digest"]); _plan_labels(obj["credential_roles"], minimum=0)
    return copy.deepcopy(obj)


def validate_runner_plan_request(value: Any) -> dict[str, Any]:
    obj = _contract(value, 64 * 1024); _reject_keys(obj, _FORBIDDEN_DISCOVERY_KEYS)
    obj = _object(obj, {"schema_version", "plan_request_id", "plan_request_nonce", "plan_kind", "max_ops", "inventory_digest", "selection_digest", "routes", "expires_at_ms"})
    _enum(obj["schema_version"], {RUNNER_PLAN_REQUEST_SCHEMA}); _enum(obj["plan_kind"], {"plan_differential"})
    if not isinstance(obj["plan_request_id"], str) or not _PLAN_REQUEST_ID.fullmatch(obj["plan_request_id"]):
        _fail("invalid plan request id")
    if not isinstance(obj["plan_request_nonce"], str) or not _NONCE.fullmatch(obj["plan_request_nonce"]):
        _fail("invalid plan request nonce")
    _integer(obj["max_ops"], lower=1, upper=20); _hash(obj["inventory_digest"]); _hash(obj["selection_digest"])
    _route_selection(obj["routes"], maximum=10); _integer(obj["expires_at_ms"], lower=1)
    return copy.deepcopy(obj)
