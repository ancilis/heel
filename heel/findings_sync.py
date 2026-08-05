"""Privacy-minimized, project-pseudonymous findings continuity contracts."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from .review_contract import stable_json, stable_json_hash, validate_review_envelope


FINDINGS_SYNC_SCHEMA_VERSION = "heel.findings-sync.v1"
FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION = "heel.findings-sync-receipt.v1"
SUPPORTED_SOURCE_ENGINE_VERSIONS = frozenset({"1.1.0", "1.1.1", "1.2.0"})
SUPPORTED_SOURCE_EXECUTION_MODES = frozenset({
    "browser_local",
    "machine_local",
    "cloud_isolated",
})
MAX_FINDINGS_SYNC_BYTES = 256 * 1024
MAX_FINDINGS_SYNC_RECEIPT_BYTES = 8 * 1024
MAX_FINDINGS = 512
MAX_JSON_DEPTH = 16

_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_PROJECT_REF = re.compile(r"prj_[0-9a-f]{32}\Z")
_SOURCE_RESULT_REF = re.compile(r"src1_[0-9a-f]{64}\Z")
_SURFACE_REF = re.compile(r"surf1_[0-9a-f]{64}\Z")
_FINDING_ID = re.compile(r"find1_[0-9a-f]{64}\Z")
_RECEIPT_ID = re.compile(r"fsr_[0-9a-f]{32}\Z")
_SYNCED_REVIEW_ID = re.compile(r"synrev_[0-9a-f]{32}\Z")
_ACCEPTED_AT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z\Z"
)

_REQUEST_FIELDS = (
    "schema_version",
    "project_ref",
    "source",
    "gate_status",
    "summary",
    "findings",
    "projection_hash",
)
_SOURCE_FIELDS = ("engine_version", "execution_mode", "result_ref")
_SUMMARY_FIELDS = ("findings", "blockers")
_FINDING_FIELDS = (
    "finding_id",
    "surface_ref",
    "surface_type",
    "risk_code",
    "control_code",
    "severity",
    "reachable",
)
_RECEIPT_FIELDS = (
    "schema_version",
    "receipt_id",
    "project_ref",
    "request_digest",
    "projection_hash",
    "synced_review_id",
    "disposition",
    "metered",
    "accepted_at",
)

# risk: (review control text, wire control code, allowed surfaces, allowed states)
_RISK_CATALOG = {
    "export_without_entitlement": (
        "server-side entitlement check",
        "server_side_entitlement_check",
        frozenset({"endpoints_routes", "exports"}),
        frozenset({("warn", False), ("block", True)}),
    ),
    "export_without_tenant_quota": (
        "tenant quota",
        "tenant_quota",
        frozenset({"endpoints_routes", "exports"}),
        frozenset({("warn", False), ("block", True)}),
    ),
    "endpoint_without_tenant_filter": (
        "tenant filter",
        "tenant_filter",
        frozenset({"endpoints_routes"}),
        frozenset({("warn", False), ("block", True)}),
    ),
    "ui_backing_endpoint_paid_api_bypass": (
        "shared UI/API entitlement and lookup quota",
        "shared_ui_api_entitlement_and_lookup_quota",
        frozenset({"endpoints_routes"}),
        frozenset({("warn", False), ("block", True)}),
    ),
    "unmetered_billable_resource": (
        "server-side meter accounting and cost ceiling",
        "server_side_meter_accounting_and_cost_ceiling",
        frozenset({"meters", "billing_objects"}),
        frozenset({("warn", False), ("warn", True)}),
    ),
    "stackable_coupon_without_redemption_limit": (
        "redemption limit and proof of uniqueness",
        "redemption_limit_and_proof_of_uniqueness",
        frozenset({"coupons_promotions"}),
        frozenset({("warn", False), ("warn", True), ("block", True)}),
    ),
    "oauth_scope_overbroad": (
        "OAuth scope minimization and approval",
        "oauth_scope_minimization_and_approval",
        frozenset({"integration_oauth_apps"}),
        frozenset({("warn", False), ("warn", True), ("block", True)}),
    ),
    "admin_action_without_role_or_audit_control": (
        "admin role gate and audit event",
        "admin_role_gate_and_audit_event",
        frozenset({"support_admin_actions"}),
        frozenset({("warn", False), ("warn", True), ("block", True)}),
    ),
    "agent_surface_overscope": (
        "tool scope minimization",
        "tool_scope_minimization",
        frozenset({"agent_tools", "mcp_connectors"}),
        frozenset({("block", True)}),
    ),
    "feature_flag_plan_mismatch": (
        "server-side feature entitlement check",
        "server_side_feature_entitlement_check",
        frozenset({"features_flags"}),
        frozenset({("warn", False), ("warn", True)}),
    ),
    "tenant_or_data_control_change": (
        "tenant/data control review",
        "tenant_data_control_review",
        frozenset({"data_classes", "declared_controls"}),
        frozenset({("warn", False)}),
    ),
}


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("JSON constants are forbidden")


def _nesting_within_limit(payload: bytes) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif byte in (0x5D, 0x7D):
            depth -= 1
    return True


def _parse_json(source: str, *, maximum_bytes: int, label: str) -> Any:
    if type(source) is not str:
        raise ValueError(f"{label} must be JSON text")
    if len(source) > maximum_bytes:
        raise ValueError(f"{label} exceeds its size limit")
    try:
        payload = source.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{label} contains invalid Unicode") from None
    if len(payload) > maximum_bytes:
        raise ValueError(f"{label} exceeds its size limit")
    if not _nesting_within_limit(payload):
        raise ValueError(f"{label} exceeds its nesting limit")
    try:
        return json.loads(
            source,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError:
        raise ValueError(f"{label} contains duplicate fields") from None
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError):
        raise ValueError(f"{label} is not valid JSON") from None


def _preflight_json_graph(
    value: Any,
    *,
    label: str,
    maximum_nodes: int,
    maximum_container_items: int,
) -> None:
    """Bound decoded-object work before canonical serialization or copying."""
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > maximum_nodes or depth > MAX_JSON_DEPTH:
            raise ValueError(f"{label} exceeds its complexity limit")
        if type(current) is dict:
            if len(current) > maximum_container_items:
                raise ValueError(f"{label} exceeds its complexity limit")
            for key, child in current.items():
                if type(key) is not str or len(key) > 256:
                    raise ValueError(f"{label} is outside the portable JSON contract")
                stack.append((child, depth + 1))
        elif type(current) is list:
            if len(current) > maximum_container_items:
                raise ValueError(f"{label} exceeds its complexity limit")
            stack.extend((child, depth + 1) for child in current)
        elif type(current) is str:
            if len(current) > 256:
                raise ValueError(f"{label} exceeds its complexity limit")
        elif current is None or type(current) is bool:
            continue
        elif type(current) is int:
            if not -(2**53 - 1) <= current <= 2**53 - 1:
                raise ValueError(f"{label} is outside the portable JSON contract")
        else:
            raise ValueError(f"{label} is outside the portable JSON contract")


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{path} must be an object")
    return value


def _require_exact_fields(
    value: dict[str, Any], expected: tuple[str, ...], path: str
) -> None:
    if frozenset(value) != frozenset(expected):
        raise ValueError(f"{path} must contain exactly the v1 fields")


def _require_pattern(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{path} has invalid syntax")
    return value


def _require_digest(value: Any, path: str) -> str:
    return _require_pattern(value, _SHA256_HEX, path)


def _require_boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{path} must be a boolean")
    return value


def _require_count(value: Any, path: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_FINDINGS:
        raise ValueError(f"{path} must be an integer within the v1 limit")
    return value


def _require_namespace_key(namespace_key: Any) -> bytes:
    if type(namespace_key) is not bytes or len(namespace_key) != 32:
        raise ValueError("namespace_key must be exactly 32 bytes")
    return namespace_key


def _tagged_hmac(namespace_key: bytes, tag: str, values: list[str]) -> str:
    material = stable_json(
        [FINDINGS_SYNC_SCHEMA_VERSION, tag, *values]
    ).encode("utf-8")
    return hmac.new(namespace_key, material, hashlib.sha256).hexdigest()


def _catalog_entry(
    risk: Any,
    surface_type: Any,
    severity: Any,
    reachable: Any,
    *,
    raw_control: Any | None = None,
    control_code: Any | None = None,
) -> tuple[str, str]:
    if type(risk) is not str or risk not in _RISK_CATALOG:
        raise ValueError("finding risk is outside the closed v1 catalog")
    expected_raw, expected_code, surfaces, states = _RISK_CATALOG[risk]
    if type(surface_type) is not str or surface_type not in surfaces:
        raise ValueError("finding surface is invalid for its risk")
    if type(severity) is not str or (severity, reachable) not in states:
        raise ValueError("finding severity/reachability state is invalid")
    if raw_control is not None and (
        type(raw_control) is not str
        or raw_control != expected_raw
    ):
        raise ValueError("finding control is outside the closed v1 catalog")
    if control_code is not None and (
        type(control_code) is not str
        or control_code != expected_code
    ):
        raise ValueError("finding control code is invalid for its risk")
    return expected_raw, expected_code


def _projection_material(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": request["schema_version"],
        "gate_status": request["gate_status"],
        "summary": request["summary"],
        "findings": request["findings"],
    }


def project_findings_sync(
    review: dict[str, Any], project_ref: str, namespace_key: bytes
) -> dict[str, Any]:
    """Project a complete local review into the maximum findings-only disclosure."""
    key = _require_namespace_key(namespace_key)
    project = _require_pattern(project_ref, _PROJECT_REF, "project_ref")
    validated_review = validate_review_envelope(review)
    if len(validated_review["findings"]) > MAX_FINDINGS:
        raise ValueError("review contains too many findings to sync")

    findings = []
    identities: set[str] = set()
    for finding in validated_review["findings"]:
        risk = finding["risk"]
        surface_type = finding["surface_type"]
        reachable = finding["reachable"]
        severity = finding["severity"]
        _raw_control, control_code = _catalog_entry(
            risk,
            surface_type,
            severity,
            reachable,
            raw_control=finding["control"],
        )
        surface_ref = "surf1_" + _tagged_hmac(
            key,
            "surface",
            [surface_type, finding["surface_id"]],
        )
        finding_id = "find1_" + _tagged_hmac(
            key,
            "finding",
            [surface_ref, risk],
        )
        if finding_id in identities:
            raise ValueError("review contains a duplicate sync finding identity")
        identities.add(finding_id)
        findings.append({
            "finding_id": finding_id,
            "surface_ref": surface_ref,
            "surface_type": surface_type,
            "risk_code": risk,
            "control_code": control_code,
            "severity": severity,
            "reachable": reachable,
        })
    findings.sort(key=lambda item: item["finding_id"])
    blockers = sum(item["severity"] == "block" for item in findings)
    request = {
        "schema_version": FINDINGS_SYNC_SCHEMA_VERSION,
        "project_ref": project,
        "source": {
            "engine_version": validated_review["engine_version"],
            "execution_mode": validated_review["execution_mode"],
            "result_ref": "src1_" + _tagged_hmac(
                key,
                "source",
                [validated_review["result_hash"]],
            ),
        },
        "gate_status": "block" if blockers else "warn" if findings else "pass",
        "summary": {"findings": len(findings), "blockers": blockers},
        "findings": findings,
    }
    request["projection_hash"] = stable_json_hash(_projection_material(request))
    return validate_findings_sync_request(request, key)


def validate_findings_sync_request(
    value: Any, namespace_key: bytes
) -> dict[str, Any]:
    """Validate and detach a complete ``heel.findings-sync.v1`` request."""
    key = _require_namespace_key(namespace_key)
    _preflight_json_graph(
        value,
        label="findings sync request",
        maximum_nodes=10_000,
        maximum_container_items=MAX_FINDINGS,
    )
    item = _require_object(value, "request")
    _require_exact_fields(item, _REQUEST_FIELDS, "request")
    if item["schema_version"] != FINDINGS_SYNC_SCHEMA_VERSION:
        raise ValueError("request schema_version is unsupported")
    _require_pattern(item["project_ref"], _PROJECT_REF, "project_ref")

    source = _require_object(item["source"], "source")
    _require_exact_fields(source, _SOURCE_FIELDS, "source")
    if (
        type(source["engine_version"]) is not str
        or source["engine_version"] not in SUPPORTED_SOURCE_ENGINE_VERSIONS
    ):
        raise ValueError("source.engine_version is unsupported")
    if (
        type(source["execution_mode"]) is not str
        or source["execution_mode"] not in SUPPORTED_SOURCE_EXECUTION_MODES
    ):
        raise ValueError("source.execution_mode is unsupported")
    _require_pattern(source["result_ref"], _SOURCE_RESULT_REF, "source.result_ref")

    summary = _require_object(item["summary"], "summary")
    _require_exact_fields(summary, _SUMMARY_FIELDS, "summary")
    finding_count = _require_count(summary["findings"], "summary.findings")
    blocker_count = _require_count(summary["blockers"], "summary.blockers")

    if type(item["findings"]) is not list:
        raise ValueError("findings must be an array")
    if len(item["findings"]) > MAX_FINDINGS:
        raise ValueError("findings exceeds the v1 count limit")
    findings: list[dict[str, Any]] = []
    finding_ids: set[str] = set()
    compound_ids: set[tuple[str, str]] = set()
    for index, value_finding in enumerate(item["findings"]):
        path = f"findings[{index}]"
        finding = _require_object(value_finding, path)
        _require_exact_fields(finding, _FINDING_FIELDS, path)
        finding_id = _require_pattern(finding["finding_id"], _FINDING_ID, f"{path}.finding_id")
        surface_ref = _require_pattern(finding["surface_ref"], _SURFACE_REF, f"{path}.surface_ref")
        reachable = _require_boolean(finding["reachable"], f"{path}.reachable")
        risk = finding["risk_code"]
        _raw_control, control_code = _catalog_entry(
            risk,
            finding["surface_type"],
            finding["severity"],
            reachable,
            control_code=finding["control_code"],
        )
        expected_id = "find1_" + _tagged_hmac(
            key,
            "finding",
            [surface_ref, risk],
        )
        if not hmac.compare_digest(finding_id, expected_id):
            raise ValueError("finding_id does not match its pseudonymous identity")
        compound = (surface_ref, risk)
        if finding_id in finding_ids or compound in compound_ids:
            raise ValueError("request contains a duplicate finding identity")
        finding_ids.add(finding_id)
        compound_ids.add(compound)
        findings.append({
            "finding_id": finding_id,
            "surface_ref": surface_ref,
            "surface_type": finding["surface_type"],
            "risk_code": risk,
            "control_code": control_code,
            "severity": finding["severity"],
            "reachable": reachable,
        })
    if findings != sorted(findings, key=lambda finding: finding["finding_id"]):
        raise ValueError("findings must use canonical v1 ordering")
    blockers = sum(finding["severity"] == "block" for finding in findings)
    if finding_count != len(findings) or blocker_count != blockers:
        raise ValueError("summary does not match findings")
    expected_gate = "block" if blockers else "warn" if findings else "pass"
    if item["gate_status"] != expected_gate:
        raise ValueError("gate_status does not match findings")
    projection_hash = _require_digest(item["projection_hash"], "projection_hash")
    normalized = {
        "schema_version": FINDINGS_SYNC_SCHEMA_VERSION,
        "project_ref": item["project_ref"],
        "source": {
            "engine_version": source["engine_version"],
            "execution_mode": source["execution_mode"],
            "result_ref": source["result_ref"],
        },
        "gate_status": expected_gate,
        "summary": {"findings": finding_count, "blockers": blocker_count},
        "findings": findings,
        "projection_hash": projection_hash,
    }
    expected_projection = stable_json_hash(_projection_material(normalized))
    if not hmac.compare_digest(projection_hash, expected_projection):
        raise ValueError("projection_hash does not match the projection")
    if len(stable_json(normalized).encode("utf-8")) > MAX_FINDINGS_SYNC_BYTES:
        raise ValueError("canonical findings sync request exceeds its size limit")
    return normalized


def parse_findings_sync_request(
    source: str, namespace_key: bytes
) -> dict[str, Any]:
    """Parse duplicate-free bounded JSON and validate a findings sync request."""
    parsed = _parse_json(
        source,
        maximum_bytes=MAX_FINDINGS_SYNC_BYTES,
        label="findings sync request",
    )
    return validate_findings_sync_request(parsed, namespace_key)


def findings_sync_request_digest(value: Any, namespace_key: bytes) -> str:
    """Return the idempotency/approval digest for a validated complete request."""
    return stable_json_hash(validate_findings_sync_request(value, namespace_key))


def _valid_accepted_at(value: Any) -> bool:
    if type(value) is not str:
        return False
    match = _ACCEPTED_AT.fullmatch(value)
    if match is None:
        return False
    year, month, day, hour, minute, second, _millisecond = (
        int(part) for part in match.groups()
    )
    if year < 1 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59:
        return False
    days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        days[1] = 29
    return 1 <= day <= days[month - 1]


def validate_findings_sync_receipt(value: Any) -> dict[str, Any]:
    """Validate and detach an exact findings-sync receipt."""
    _preflight_json_graph(
        value,
        label="findings sync receipt",
        maximum_nodes=256,
        maximum_container_items=64,
    )
    item = _require_object(value, "receipt")
    _require_exact_fields(item, _RECEIPT_FIELDS, "receipt")
    if item["schema_version"] != FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION:
        raise ValueError("receipt schema_version is unsupported")
    _require_pattern(item["receipt_id"], _RECEIPT_ID, "receipt_id")
    _require_pattern(item["project_ref"], _PROJECT_REF, "project_ref")
    _require_digest(item["request_digest"], "request_digest")
    _require_digest(item["projection_hash"], "projection_hash")
    _require_pattern(item["synced_review_id"], _SYNCED_REVIEW_ID, "synced_review_id")
    if (
        type(item["disposition"]) is not str
        or item["disposition"] not in {"created", "reused"}
    ):
        raise ValueError("receipt disposition is unsupported")
    metered = _require_boolean(item["metered"], "metered")
    if metered != (item["disposition"] == "created"):
        raise ValueError("receipt metering contradicts its disposition")
    if not _valid_accepted_at(item["accepted_at"]):
        raise ValueError("accepted_at must be a valid canonical UTC timestamp")
    normalized = {
        "schema_version": FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION,
        "receipt_id": item["receipt_id"],
        "project_ref": item["project_ref"],
        "request_digest": item["request_digest"],
        "projection_hash": item["projection_hash"],
        "synced_review_id": item["synced_review_id"],
        "disposition": item["disposition"],
        "metered": metered,
        "accepted_at": item["accepted_at"],
    }
    if len(stable_json(normalized).encode("utf-8")) > MAX_FINDINGS_SYNC_RECEIPT_BYTES:
        raise ValueError("canonical findings sync receipt exceeds its size limit")
    return normalized


def parse_findings_sync_receipt(source: str) -> dict[str, Any]:
    """Parse duplicate-free bounded JSON and validate a findings-sync receipt."""
    parsed = _parse_json(
        source,
        maximum_bytes=MAX_FINDINGS_SYNC_RECEIPT_BYTES,
        label="findings sync receipt",
    )
    return validate_findings_sync_receipt(parsed)
