"""Versioned, JSON-only review contract shared by native, browser, MCP, and cloud clients."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


REVIEW_SCHEMA_VERSION = "heel.review.v1"
ENGINE_VERSION = "1.1.0"
EXECUTION_MODES = {"browser_local", "machine_local", "cloud_isolated"}


def stable_json(value: Any) -> str:
    """Serialize a JSON value in its canonical UTF-8-preserving representation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_json_hash(value: Any) -> str:
    """Return the SHA-256 digest of a value's canonical JSON representation."""
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def build_review_envelope(
    review: Mapping[str, Any], *, source_hash: str, model_hash: str,
    baseline_hash: str | None, execution_mode: str,
    questions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the deterministic, versioned envelope shared by every execution surface."""
    if execution_mode not in EXECUTION_MODES:
        raise ValueError(f"unsupported execution_mode: {execution_mode}")

    findings = [dict(item) for item in review.get("new_abuse_affordances", [])]
    findings.sort(key=lambda item: (
        0 if item.get("severity") == "block" else 1,
        str(item.get("surface_type", "")),
        str(item.get("surface_id", "")),
        str(item.get("risk", "")),
    ))
    normalized_questions = [dict(item) for item in questions]
    envelope = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "product_id": str(review.get("product_id", "")),
        "source_hash": source_hash,
        "model_hash": model_hash,
        "baseline_hash": baseline_hash,
        "execution_mode": execution_mode,
        "gate_status": str(review.get("launch_gate_status", "pass")),
        "summary": {
            "findings": len(findings),
            "blockers": sum(item.get("severity") == "block" for item in findings),
            "questions": len(normalized_questions),
        },
        "findings": findings,
        "recommended_controls": [dict(item) for item in review.get("recommended_controls", [])],
        "suggested_regressions": [dict(item) for item in review.get("suggested_regression_tests", [])],
        "questions": normalized_questions,
        "safety": dict(review.get("safety", {})),
        "privacy": {
            "execution": execution_mode,
            "network_calls": False,
            "uploaded": False,
            "sync_intent": "none",
        },
    }
    result_hash = stable_json_hash(envelope)
    return {"review_id": "review_" + result_hash[:20], "result_hash": result_hash, **envelope}
