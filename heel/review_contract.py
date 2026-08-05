"""Versioned, JSON-only review contract shared by native, browser, MCP, and cloud clients."""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Mapping, Sequence


REVIEW_SCHEMA_VERSION = "heel.review.v1"
ENGINE_VERSION = "1.1.0"
EXECUTION_MODES = frozenset({"browser_local", "machine_local", "cloud_isolated"})

_JS_SAFE_INTEGER = 2**53 - 1
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_FINDING_FIELDS = (
    "surface_type",
    "surface_id",
    "risk",
    "severity",
    "control",
    "reason",
    "reachable",
)
_REGRESSION_FIELDS = (
    "surface_type",
    "surface_id",
    "name",
    "expected_status",
    "scenario_hint",
    "safety",
)
_QUESTION_FIELDS = ("id", "field", "surface", "prompt", "required")
_SAFETY_FIELDS = (
    "mode",
    "live_probing",
    "network_calls",
    "requires_signed_scope_for_live_or_staging_runs",
    "canary_only",
)


def _validate_unicode(value: str, path: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError(f"{path} contains a lone Unicode surrogate")


def _normalize_json(value: Any, path: str = "value") -> Any:
    """Validate and deep-copy the portable JSON subset used by every Heel surface."""
    if value is None or type(value) is bool:
        return value
    if type(value) is str:
        _validate_unicode(value, path)
        return value
    if type(value) is int:
        if not -_JS_SAFE_INTEGER <= value <= _JS_SAFE_INTEGER:
            raise ValueError(f"{path} contains an integer outside the JavaScript-safe range")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite float")
        return 0.0 if value == 0.0 else value
    if type(value) is list:
        return [_normalize_json(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if type(value) is dict:
        normalized = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError(f"{path} contains a non-string mapping key")
            _validate_unicode(key, f"{path} key")
            normalized[key] = _normalize_json(item, f"{path}.{key}")
        return normalized
    raise ValueError(f"{path} contains a value outside the JSON data model")


def stable_json(value: Any) -> str:
    """Serialize portable JSON canonically while preserving Unicode scalar values."""
    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def stable_json_hash(value: Any) -> str:
    """Return the SHA-256 digest of a value's canonical JSON representation."""
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{path} must be a JSON object")
    return value


def _require_array(value: Any, path: str) -> list[Any]:
    if type(value) is not list:
        raise ValueError(f"{path} must be a JSON array")
    return value


def _require_nonempty_string(value: Any, path: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{path} must be a nonempty string")
    return value


def _require_boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{path} must be a boolean")
    return value


def _require_exact_fields(record: dict[str, Any], fields: tuple[str, ...], path: str) -> None:
    actual = frozenset(record)
    expected = frozenset(fields)
    if actual != expected:
        raise ValueError(f"{path} must contain exactly the v1 fields")


def _validate_finding(record: Any, path: str) -> dict[str, Any]:
    item = _require_object(record, path)
    _require_exact_fields(item, _FINDING_FIELDS, path)
    normalized = {
        field: _require_nonempty_string(item[field], f"{path}.{field}")
        for field in _FINDING_FIELDS[:-1]
    }
    if normalized["severity"] not in {"warn", "block"}:
        raise ValueError(f"{path}.severity must be warn or block")
    normalized["reachable"] = _require_boolean(item["reachable"], f"{path}.reachable")
    return normalized


def _validate_findings(records: Any, path: str) -> list[dict[str, Any]]:
    return [
        _validate_finding(record, f"{path}[{index}]")
        for index, record in enumerate(_require_array(records, path))
    ]


def _validate_regressions(records: Any, path: str) -> list[dict[str, Any]]:
    normalized = []
    for index, record in enumerate(_require_array(records, path)):
        item_path = f"{path}[{index}]"
        item = _require_object(record, item_path)
        _require_exact_fields(item, _REGRESSION_FIELDS, item_path)
        normalized.append({
            field: _require_nonempty_string(item[field], f"{item_path}.{field}")
            for field in _REGRESSION_FIELDS
        })
    return normalized


def _validate_questions(records: Any) -> list[dict[str, Any]]:
    path = "questions"
    normalized = []
    for index, record in enumerate(_require_array(records, path)):
        item_path = f"{path}[{index}]"
        item = _require_object(record, item_path)
        _require_exact_fields(item, _QUESTION_FIELDS, item_path)
        normalized_item = {
            field: _require_nonempty_string(item[field], f"{item_path}.{field}")
            for field in _QUESTION_FIELDS[:-1]
        }
        normalized_item["required"] = _require_boolean(item["required"], f"{item_path}.required")
        normalized.append(normalized_item)
    return normalized


def _validate_safety(value: Any) -> dict[str, Any]:
    path = "safety"
    item = _require_object(value, path)
    _require_exact_fields(item, _SAFETY_FIELDS, path)
    return {
        "mode": _require_nonempty_string(item["mode"], "safety.mode"),
        "live_probing": _require_boolean(item["live_probing"], "safety.live_probing"),
        "network_calls": _require_boolean(item["network_calls"], "safety.network_calls"),
        "requires_signed_scope_for_live_or_staging_runs": _require_boolean(
            item["requires_signed_scope_for_live_or_staging_runs"],
            "safety.requires_signed_scope_for_live_or_staging_runs",
        ),
        "canary_only": _require_boolean(item["canary_only"], "safety.canary_only"),
    }


def _validate_hash(value: Any, path: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or _SHA256_HEX.fullmatch(value) is None:
        raise ValueError(f"{path} must be a lowercase 64-character SHA-256 hex digest")
    return value


def build_review_envelope(
    review: Mapping[str, Any], *, source_hash: str, model_hash: str,
    baseline_hash: str | None, execution_mode: str,
    questions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate and build the deterministic envelope shared by every execution surface."""
    if type(execution_mode) is not str or execution_mode not in EXECUTION_MODES:
        raise ValueError(f"unsupported execution_mode: {execution_mode}")

    review_input = _require_object(_normalize_json(review, "review"), "review")
    product_id = _require_nonempty_string(review_input.get("product_id"), "product_id")
    gate_status = review_input.get("launch_gate_status")
    if type(gate_status) is not str or gate_status not in {"pass", "warn", "block"}:
        raise ValueError("launch_gate_status must be pass, warn, or block")

    findings = _validate_findings(
        review_input.get("new_abuse_affordances"),
        "new_abuse_affordances",
    )
    controls = _validate_findings(
        review_input.get("recommended_controls"),
        "recommended_controls",
    )
    regressions = _validate_regressions(
        review_input.get("suggested_regression_tests"),
        "suggested_regression_tests",
    )
    normalized_safety = _validate_safety(review_input.get("safety"))
    normalized_questions = _validate_questions(_normalize_json(questions, "questions"))

    blockers = sum(item["severity"] == "block" for item in findings)
    expected_gate = "block" if blockers else "warn" if findings else "pass"
    if gate_status != expected_gate:
        raise ValueError(
            f"launch_gate_status must be {expected_gate} for the supplied findings"
        )

    findings.sort(key=lambda item: (
        0 if item["severity"] == "block" else 1,
        item["surface_type"],
        item["surface_id"],
        item["risk"],
        stable_json(item),
    ))
    controls.sort(key=stable_json)
    regressions.sort(key=stable_json)
    normalized_questions.sort(key=stable_json)

    privacy = {
        "execution": execution_mode,
        "network_calls": False,
        "uploaded": execution_mode == "cloud_isolated",
        "sync_intent": "sanitized_model" if execution_mode == "cloud_isolated" else "none",
    }
    envelope = _normalize_json({
        "schema_version": REVIEW_SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "product_id": product_id,
        "source_hash": _validate_hash(source_hash, "source_hash"),
        "model_hash": _validate_hash(model_hash, "model_hash"),
        "baseline_hash": _validate_hash(baseline_hash, "baseline_hash", allow_none=True),
        "execution_mode": execution_mode,
        "gate_status": gate_status,
        "summary": {
            "findings": len(findings),
            "blockers": blockers,
            "questions": len(normalized_questions),
        },
        "findings": findings,
        "recommended_controls": controls,
        "suggested_regressions": regressions,
        "questions": normalized_questions,
        "safety": normalized_safety,
        "privacy": privacy,
    }, "envelope")
    result_hash = stable_json_hash(envelope)
    return {"review_id": "review_" + result_hash[:20], "result_hash": result_hash, **envelope}
