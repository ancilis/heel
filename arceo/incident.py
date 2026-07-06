"""
Incident-to-scenario workflow.

This module converts operator-sanitized abuse incidents into local scenario and
regression drafts. It never enables a scenario automatically and never touches
authorization scopes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Mapping

from .contracts import Category
from .scope import ensure_home


ALLOWED_SOURCES = {"manual", "ticket", "postmortem", "trust_safety"}
REQUIRED_FIELDS = [
    "incident_id",
    "summary",
    "product_area",
    "affected_surfaces",
    "customer_type",
    "abuse_goal",
    "steps_observed",
    "business_impact",
    "controls_missing",
    "controls_added",
    "data_classes",
    "sanitized_evidence",
    "prohibited_fields_removed_confirmed",
    "source",
    "safety_notes",
]
LIST_FIELDS = {
    "affected_surfaces",
    "steps_observed",
    "controls_missing",
    "controls_added",
    "data_classes",
    "safety_notes",
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRET_KEY_RE = re.compile(
    r"(?i)(^|[_\-.])(api[_\-.]?key|secret|token|password|passwd|private[_\-.]?key|"
    r"client[_\-.]?secret|access[_\-.]?key|refresh[_\-.]?token|session[_\-.]?cookie|"
    r"cookie|authorization|bearer)($|[_\-.])"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(sk-(live|test)?[-_a-z0-9]{8,}|xox[baprs]-[-_a-z0-9]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._~+/=-]{12,})"
)
_CUSTOMER_IDENTIFYING_KEY_RE = re.compile(
    r"(?i)(^|[_\-.])(customer|user|account|tenant|email|phone|ip|name|session)($|[_\-.])"
)
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PAYLOAD_RE = re.compile(r"(?i)(raw[_\-.]?payload|exploit[_\-.]?payload|curl\s+https?://|drop\s+table|<script)")


class IncidentError(ValueError):
    """Raised when an incident cannot be imported or drafted safely."""


def _read_json(path: str | os.PathLike[str]) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise IncidentError(f"invalid JSON: {exc}") from exc
    except OSError as exc:
        raise IncidentError(f"cannot read incident: {exc}") from exc
    if not isinstance(data, dict):
        raise IncidentError("incident must be a JSON object")
    return data


def _write_json(path: str, data: Mapping[str, Any]) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def _paths() -> tuple[str, str]:
    home = ensure_home()
    return os.path.join(home, "incidents"), os.path.join(home, "drafts")


def _incident_path(incident_id: str) -> str:
    incidents_dir, _ = _paths()
    return os.path.join(incidents_dir, f"{incident_id}.json")


def _draft_path(incident_id: str, suffix: str = "scenario") -> str:
    _, drafts_dir = _paths()
    return os.path.join(drafts_dir, f"{incident_id}.{suffix}.json")


def _stable_slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value.strip()).strip("-").lower()
    return cleaned[:80] or hashlib.sha1(value.encode()).hexdigest()[:12]


def _scan_value(value: Any, path: str, errors: list[str], *, evidence: bool = False) -> None:
    if isinstance(value, Mapping):
        for key, child_value in value.items():
            key_s = str(key)
            child = f"{path}.{key_s}"
            if _SECRET_KEY_RE.search(key_s):
                errors.append(f"{child}: field name looks secret-bearing")
            if evidence and _CUSTOMER_IDENTIFYING_KEY_RE.search(key_s) and key_s not in {"evidence_id"}:
                errors.append(f"{child}: field name looks customer-identifying")
            if _PAYLOAD_RE.search(key_s):
                errors.append(f"{child}: field name looks payload-bearing")
            _scan_value(child_value, child, errors, evidence=evidence)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _scan_value(item, f"{path}[{i}]", errors, evidence=evidence)
    elif isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            errors.append(f"{path}: value looks secret-bearing")
        if _EMAIL_RE.search(value):
            errors.append(f"{path}: value looks customer-identifying")
        if _PAYLOAD_RE.search(value):
            errors.append(f"{path}: value looks payload-bearing")


def validate_incident(data: Mapping[str, Any]) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, Mapping):
        raise IncidentError("incident must be a JSON object")

    for field in REQUIRED_FIELDS:
        if field not in data:
            errors.append(f"missing required field: {field}")
    incident_id = str(data.get("incident_id", ""))
    if incident_id and not _ID_RE.match(incident_id):
        errors.append("incident_id must be a stable ASCII identifier without whitespace")
    for field in ("summary", "product_area", "customer_type", "abuse_goal", "source"):
        if field in data and not (isinstance(data[field], str) and data[field].strip()):
            errors.append(f"{field} must be a non-empty string")
    for field in LIST_FIELDS:
        if field in data and (not isinstance(data[field], list) or not data[field]):
            errors.append(f"{field} must be a non-empty list")
    if "business_impact" in data and not isinstance(data["business_impact"], Mapping):
        errors.append("business_impact must be an object")
    if "sanitized_evidence" in data and not isinstance(data["sanitized_evidence"], Mapping):
        errors.append("sanitized_evidence must be an object")
    if data.get("prohibited_fields_removed_confirmed") is not True:
        errors.append("prohibited_fields_removed_confirmed must be true")
    if data.get("source") not in ALLOWED_SOURCES:
        errors.append("source must be manual, ticket, postmortem, or trust_safety")

    _scan_value(data, "$", errors)
    if isinstance(data.get("sanitized_evidence"), Mapping):
        _scan_value(data["sanitized_evidence"], "$.sanitized_evidence", errors, evidence=True)
    if not data.get("controls_missing"):
        warnings.append("controls_missing is empty; draft will use a conservative recommended control")

    if errors:
        raise IncidentError("; ".join(errors))
    return {
        "ok": True,
        "incident_id": incident_id,
        "warnings": warnings,
        "summary": f"sanitized incident {incident_id}: {data.get('summary', '')}",
    }


def load_incident(incident_id: str) -> dict:
    path = _incident_path(incident_id)
    if not os.path.exists(path):
        raise IncidentError(f"unknown incident_id '{incident_id}'")
    return _read_json(path)


def import_incident(path: str | os.PathLike[str]) -> dict:
    data = _read_json(path)
    validation = validate_incident(data)
    incident_id = validation["incident_id"]
    stored = json.loads(json.dumps(data, default=str))
    stored["_arceo_incident"] = {
        "imported_at": time.time(),
        "sanitized": True,
        "prohibited_fields_removed_confirmed": True,
    }
    stored_path = _write_json(_incident_path(incident_id), stored)
    return {
        "incident_id": incident_id,
        "stored_path": stored_path,
        "validation": validation,
        "incident": stored,
    }


def _text(data: Mapping[str, Any]) -> str:
    fields = [
        data.get("summary", ""),
        data.get("product_area", ""),
        data.get("abuse_goal", ""),
        " ".join(str(x) for x in data.get("affected_surfaces", [])),
        " ".join(str(x) for x in data.get("controls_missing", [])),
    ]
    return " ".join(fields).lower()


def _mapping(data: Mapping[str, Any]) -> dict:
    text = _text(data)
    if any(word in text for word in ("coupon", "promotion", "discount", "trial", "pricing", "billing")):
        return {
            "category": Category.LICENSE_ENTITLEMENT.value,
            "persona": "coupon_stacker",
            "kind": "promotion",
            "criterion_prop": "coupon_stacking",
            "recommended_control": "single active coupon per account plus promotion velocity limits",
            "pack": "payments_billing",
        }
    if any(word in text for word in ("export", "scrap", "bulk download", "download", "csv")):
        return {
            "category": Category.DATA_HARVESTING.value,
            "persona": "data_broker",
            "kind": "export",
            "criterion_prop": "export_scraping",
            "recommended_control": "entitlement check plus per-tenant export rate limits",
            "pack": "core_saas",
        }
    if any(word in text for word in ("support", "workflow", "refund", "approval", "manual")):
        return {
            "category": Category.FUNCTION_ABUSE.value,
            "persona": "support_workflow_gamer",
            "kind": "support_workflow",
            "criterion_prop": "support_workflow_bypass",
            "recommended_control": "dual approval and audit event for support workflow overrides",
            "pack": "trust_safety",
        }
    return {
        "category": Category.TRUST_ECONOMY.value,
        "persona": "opportunistic_abuser",
        "kind": "workflow",
        "criterion_prop": "abuse_pattern_observed",
        "recommended_control": "documented abuse control plus canary regression",
        "pack": "core_saas",
    }


def _severity_model(data: Mapping[str, Any]) -> dict:
    impact = data.get("business_impact") or {}
    high = None
    if isinstance(impact, Mapping):
        for value in impact.values():
            if isinstance(value, Mapping) and "high" in value:
                try:
                    high = max(float(value["high"]), high or 0)
                except (TypeError, ValueError):
                    pass
    if high is None:
        return {"likelihood": 0.4, "impact": 0.4}
    return {"likelihood": 0.5 if high < 10000 else 0.65, "impact": 0.5 if high < 10000 else 0.7}


def _scenario(data: Mapping[str, Any], mapping: Mapping[str, Any]) -> dict:
    incident_id = str(data["incident_id"])
    control = data.get("controls_added") or data.get("controls_missing") or [mapping["recommended_control"]]
    return {
        "id": f"sc.incident.{_stable_slug(incident_id)}",
        "category": mapping["category"],
        "objective": f"Rehearse sanitized incident pattern: {data['summary']}",
        "kind": mapping["kind"],
        "probe_strategy": "incident_canary_rehearsal",
        "success_criterion": {"prop": mapping["criterion_prop"], "equals": "observed"},
        "severity_model": _severity_model(data),
        "recommended_control": str(control[0]),
        "exploitability_reduction": 0.65,
        "pack": mapping["pack"],
        "source": "incident_draft",
        "classification_impact": ",".join(str(x) for x in data.get("data_classes", [])),
    }


def draft_scenario(incident_id: str) -> dict:
    data = load_incident(incident_id)
    validate_incident(data)
    mapping = _mapping(data)
    scenario = _scenario(data, mapping)
    draft = {
        "incident_id": incident_id,
        "auto_enabled": False,
        "review": "This is a local draft only. Operator review is required before adding it to scenarios_lib.",
        "mapping": mapping,
        "scenario": scenario,
        "safety": {
            "sanitized_input": True,
            "no_payloads": True,
            "canary_only": True,
            "scope_required_for_runs": True,
        },
    }
    path = _draft_path(incident_id, "scenario")
    draft["draft_path"] = path
    _write_json(path, draft)
    return draft


def add_regression_draft(incident_id: str) -> dict:
    draft = draft_scenario(incident_id)
    scenario = draft["scenario"]
    regression = {
        "regression_id": f"reg.incident.{_stable_slug(incident_id)}",
        "name": f"incident_{_stable_slug(incident_id)}",
        "source_incident_id": incident_id,
        "scenario_id": scenario["id"],
        "target_affordance_pattern": {"kind": scenario["kind"]},
        "success_criterion": dict(scenario["success_criterion"]),
        "recommended_control": scenario["recommended_control"],
        "expected_status": "blocked",
        "evidence_mode": "canary_only",
        "created_at": time.time(),
        "safety_flags": {
            "scope_required": True,
            "canary_only": True,
            "contained": True,
            "no_scope_widening": True,
            "no_payloads": True,
            "generated_from_sanitized_incident": True,
        },
        "review": "Local regression draft only; it is not runnable until an operator reviews and enables the scenario.",
    }
    path = _draft_path(incident_id, "regression")
    regression["draft_path"] = path
    _write_json(path, regression)
    return regression


def review_incident(incident_id: str) -> dict:
    scenario_draft = draft_scenario(incident_id)
    regression_draft = add_regression_draft(incident_id)
    return {
        "incident_id": incident_id,
        "auto_enabled": False,
        "review": "Operator confirmation is required before adding these drafts to the active scenario library.",
        "draft_paths": {
            "scenario": scenario_draft["draft_path"],
            "regression": regression_draft["draft_path"],
        },
        "would_add": {
            "scenario": scenario_draft["scenario"],
            "regression": {
                key: value
                for key, value in regression_draft.items()
                if key != "draft_path"
            },
        },
    }
