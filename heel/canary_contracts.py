"""Canonical, privacy-minimized contracts for verified canary execution.

The module deliberately validates only transport-safe projections: it has no network,
filesystem, crypto-provider, or application-model dependency.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
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
    obj = _object(obj, {"schema_version", "projection_id", "workspace_id", "project_id", "environment", "runner", "compiler", "scenarios", "actions", "budgets", "egress", "retry_policy", "compiled_at_ms", "manifest_digest", "projection_digest", "signing_key_id", "signature_b64"})
    _enum(obj["schema_version"], {APPROVAL_PROJECTION_SCHEMA}); _id_fields(obj, ("projection_id", "workspace_id", "project_id")); env = _environment(obj["environment"])
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
    _signature(obj, "projection_digest")
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
