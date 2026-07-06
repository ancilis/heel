"""Offline validation and explanation helpers for authored Arceo scenarios."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Mapping

from .contracts import AppliesWhen, Category, ScenarioPack


SCENARIO_ID_PREFIXES = (
    "sc.community.",
    "sc.research.",
    "sc.internal.",
    "sc.incident.",
)

AFFORDANCE_KINDS = {
    "admin_action",
    "agent_tool",
    "auth_reset",
    "billing",
    "chain",
    "content_guardrail",
    "data_class",
    "data_pipeline",
    "endpoint",
    "export",
    "flag",
    "integration",
    "mcp_connector",
    "meter",
    "oauth_app",
    "plan",
    "promotion",
    "record",
    "referral",
    "region",
    "review",
    "role",
    "seat",
    "session",
    "signup",
    "trial",
    "webhook",
}

REQUIRED_FIELDS = (
    "id",
    "category",
    "objective",
    "kind",
    "success_criterion",
    "severity_model",
    "recommended_control",
    "containment_limits",
)

DECLARATIVE_OPERATORS = {
    "semantic",
    "guard_absent",
    "prop_exists",
    "prop",
    "equals",
    "in",
    "exists",
    "prop_contains",
    "prop_neq",
    "all_of",
    "any_of",
    "not",
}

_PROHIBITED_MARKERS = (
    "payload",
    "exploit",
    "exfiltrate",
    "exfiltration",
    "real credential",
    "credential use",
    "stolen credential",
    "api key",
    "high-volume scraping",
    "high volume scraping",
    "scrape all",
    "curl ",
    "sqlmap",
    "nmap ",
    "metasploit",
    "<script",
    "drop table",
    "169.254.169.254",
    "../",
    "..\\",
)


@dataclass(frozen=True)
class ScenarioValidationResult:
    ok: bool
    scenario_id: str | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""


def validate_scenario(scenario: Mapping[str, Any]) -> ScenarioValidationResult:
    """Validate one authored scenario pack entry without executing anything."""
    errors: list[str] = []
    warnings: list[str] = []
    scenario_id = str(scenario.get("id", "")) if isinstance(scenario, Mapping) else None

    if not isinstance(scenario, Mapping):
        return ScenarioValidationResult(
            ok=False,
            scenario_id=None,
            errors=["scenario: expected a JSON object"],
            summary="invalid scenario object",
        )

    for field_name in REQUIRED_FIELDS:
        if field_name not in scenario:
            errors.append(f"{field_name}: required field is missing")

    _validate_id(scenario.get("id"), errors)
    _validate_category(scenario.get("category"), errors)
    _validate_kind(scenario.get("kind"), errors)
    _validate_applies_when(scenario.get("applies_when"), errors, warnings)
    _validate_pack(scenario.get("pack"), errors)
    _validate_nonempty_string("objective", scenario.get("objective"), errors)
    _validate_nonempty_string("recommended_control", scenario.get("recommended_control"), errors)
    _validate_severity_model(scenario.get("severity_model"), errors)
    _validate_containment_limits(scenario.get("containment_limits"), errors)
    _validate_criterion(scenario.get("success_criterion"), "success_criterion", errors)
    _scan_for_prohibited_content(scenario, "scenario", errors)

    summary = "valid authored scenario" if not errors else f"{len(errors)} validation error(s)"
    return ScenarioValidationResult(
        ok=not errors,
        scenario_id=scenario_id or None,
        errors=errors,
        warnings=warnings,
        summary=summary,
    )


def validate_scenario_file(path: str | Path) -> list[ScenarioValidationResult]:
    """Load and validate a JSON scenario object or list of scenario objects."""
    source = Path(path)
    try:
        with source.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        return [
            ScenarioValidationResult(
                ok=False,
                scenario_id=None,
                errors=[f"file: could not read scenario JSON ({exc})"],
                summary="unreadable scenario file",
            )
        ]
    except json.JSONDecodeError as exc:
        return [
            ScenarioValidationResult(
                ok=False,
                scenario_id=None,
                errors=[f"file: invalid JSON at line {exc.lineno}, column {exc.colno}"],
                summary="invalid scenario JSON",
            )
        ]

    if isinstance(data, list):
        if not data:
            return [
                ScenarioValidationResult(
                    ok=False,
                    scenario_id=None,
                    errors=["file: scenario list must not be empty"],
                    summary="empty scenario file",
                )
            ]
        return [validate_scenario(item) for item in data]
    if isinstance(data, Mapping):
        return [validate_scenario(data)]
    return [
        ScenarioValidationResult(
            ok=False,
            scenario_id=None,
            errors=["file: expected a scenario object or list of scenario objects"],
            summary="invalid scenario JSON shape",
        )
    ]


def render_validation_report(results: list[ScenarioValidationResult]) -> str:
    ok = bool(results) and all(result.ok for result in results)
    lines = [f"Scenario validation: {'PASS' if ok else 'FAIL'}"]
    for index, result in enumerate(results, 1):
        label = result.scenario_id or f"entry {index}"
        lines.append(f"  scenario: {label}")
        lines.append(f"  summary: {result.summary}")
        if result.errors:
            lines.append("  errors:")
            for error in result.errors:
                lines.append(f"    - {error}")
        if result.warnings:
            lines.append("  warnings:")
            for warning in result.warnings:
                lines.append(f"    - {warning}")
    return "\n".join(lines)


def explain_scenario(scenario_id: str) -> str | None:
    """Render a concise, safe explanation for a known scenario id."""
    from .scenarios import list_scenarios

    for scenario in list_scenarios():
        if scenario.id != scenario_id:
            continue
        kind = scenario.target_affordance_pattern.get("kind", "*")
        limits = _describe_limits(scenario.containment_limits)
        return "\n".join(
            [
                f"Scenario: {scenario.id}",
                f"Objective: {scenario.objective}",
                f"Category: {scenario.category.value}",
                f"Affordance kind: {kind}",
                f"Applies when: {scenario.applies_when.value}",
                f"Recommended control: {scenario.recommended_control}",
                f"Safety limits: {limits}",
                "Mode: declarative, canary-only rehearsal; no live target probing or scope mutation",
            ]
        )
    return None


def _validate_id(value: Any, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append("id: required non-empty string")
        return
    if not any(value.startswith(prefix) for prefix in SCENARIO_ID_PREFIXES):
        allowed = ", ".join(SCENARIO_ID_PREFIXES)
        errors.append(f"id: namespace must start with one of {allowed}")


def _validate_category(value: Any, errors: list[str]) -> None:
    try:
        Category(value)
    except Exception:
        allowed = ", ".join(category.value for category in Category)
        errors.append(f"category: unsupported category; allowed values: {allowed}")


def _validate_kind(value: Any, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append("kind: required non-empty string")
        return
    if value not in AFFORDANCE_KINDS:
        allowed = ", ".join(sorted(AFFORDANCE_KINDS))
        errors.append(f"kind: unsupported affordance kind; allowed values: {allowed}")


def _validate_applies_when(value: Any, errors: list[str], warnings: list[str]) -> None:
    if value is None:
        warnings.append("applies_when: omitted; defaults to always")
        return
    try:
        AppliesWhen(value)
    except Exception:
        allowed = ", ".join(item.value for item in AppliesWhen)
        errors.append(f"applies_when: unsupported value; allowed values: {allowed}")


def _validate_pack(value: Any, errors: list[str]) -> None:
    if value is None:
        return
    try:
        ScenarioPack(value)
    except Exception:
        allowed = ", ".join(item.value for item in ScenarioPack)
        errors.append(f"pack: unsupported value; allowed values: {allowed}")


def _validate_nonempty_string(path: str, value: Any, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: required non-empty string")


def _validate_severity_model(value: Any, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("severity_model: required object with likelihood and impact")
        return
    for key in ("likelihood", "impact"):
        if key not in value:
            errors.append(f"severity_model.{key}: required numeric value in [0,1]")
            continue
        item = value[key]
        if not isinstance(item, (int, float)) or isinstance(item, bool) or not 0 <= item <= 1:
            errors.append(f"severity_model.{key}: required numeric value in [0,1]")


def _validate_containment_limits(value: Any, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append("containment_limits: required object with canary-only limits")
        return
    canary_only = value.get("canary_only") is True or value.get("sample") == "canary_only"
    if not canary_only:
        errors.append("containment_limits: canary-only limit is required")
    if value.get("no_live_targets") is not True:
        errors.append("containment_limits.no_live_targets: must be true")

    cap_keys = ("max_examples", "max_probe_calls", "max_requests", "sample_cap")
    caps = [(key, value.get(key)) for key in cap_keys if key in value]
    if not caps:
        errors.append("containment_limits: include a bounded sample cap")
        return
    for key, cap in caps:
        if not isinstance(cap, int) or isinstance(cap, bool) or not 1 <= cap <= 20:
            errors.append(f"containment_limits.{key}: required integer in [1,20]")


def _validate_criterion(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: required declarative criterion object")
        return

    keys = set(value.keys())
    unknown = sorted(keys - DECLARATIVE_OPERATORS)
    if unknown:
        errors.append(f"{path}: unsupported operator {', '.join(unknown)}")
        return

    operator_families = [
        key for key in (
            "semantic",
            "guard_absent",
            "prop_exists",
            "prop",
            "prop_contains",
            "prop_neq",
            "all_of",
            "any_of",
            "not",
        )
        if key in value
    ]
    if len(operator_families) != 1:
        errors.append(f"{path}: unsupported operator")
        return

    operator = operator_families[0]
    if operator == "semantic":
        _validate_nonempty_string(f"{path}.semantic", value.get("semantic"), errors)
        return
    if operator == "guard_absent":
        if not isinstance(value.get("guard_absent"), bool):
            errors.append(f"{path}.guard_absent: required boolean")
        return
    if operator == "prop_exists":
        _validate_nonempty_string(f"{path}.prop_exists", value.get("prop_exists"), errors)
        return
    if operator == "prop":
        _validate_prop_criterion(value, path, errors)
        return
    if operator == "prop_contains":
        _validate_pair_operator(value.get("prop_contains"), f"{path}.prop_contains", errors)
        return
    if operator == "prop_neq":
        _validate_pair_operator(value.get("prop_neq"), f"{path}.prop_neq", errors)
        return
    if operator == "all_of":
        _validate_criterion_list(value.get("all_of"), f"{path}.all_of", errors)
        return
    if operator == "any_of":
        _validate_criterion_list(value.get("any_of"), f"{path}.any_of", errors)
        return
    if operator == "not":
        _validate_criterion(value.get("not"), f"{path}.not", errors)
        return

    errors.append(f"{path}: unsupported operator")


def _validate_prop_criterion(value: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _validate_nonempty_string(f"{path}.prop", value.get("prop"), errors)
    operator_count = sum(1 for key in ("equals", "in", "exists") if key in value)
    if operator_count != 1:
        errors.append(f"{path}: prop requires exactly one of equals, in, or exists")
        return
    if "in" in value and not isinstance(value.get("in"), list):
        errors.append(f"{path}.in: required list")
    if "exists" in value and not isinstance(value.get("exists"), bool):
        errors.append(f"{path}.exists: required boolean")


def _validate_pair_operator(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or len(value) != 2:
        errors.append(f"{path}: required two-item list")
        return
    if not all(isinstance(item, str) and item for item in value):
        errors.append(f"{path}: required two non-empty strings")


def _validate_criterion_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: required non-empty list")
        return
    for index, item in enumerate(value):
        _validate_criterion(item, f"{path}[{index}]", errors)


def _scan_for_prohibited_content(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in _PROHIBITED_MARKERS):
            errors.append(f"{path}: prohibited content or payload-like instruction is not allowed")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _scan_for_prohibited_content(item, f"{path}.{key}", errors)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _scan_for_prohibited_content(item, f"{path}[{index}]", errors)


def _describe_limits(limits: Mapping[str, Any]) -> str:
    if not limits:
        return "canary-only, no live targets, bounded samples"
    parts: list[str] = []
    if limits.get("canary_only") is True or limits.get("sample") == "canary_only":
        parts.append("canary-only")
    else:
        parts.append("canary-only by Arceo execution policy")
    if limits.get("no_live_targets") is True:
        parts.append("no live targets")
    else:
        parts.append("no live targets by default")
    for key in ("max_examples", "max_probe_calls", "max_requests", "sample_cap"):
        if key in limits:
            parts.append(f"{key}={limits[key]}")
    if not any(part.startswith("max_") or part.startswith("sample_cap") for part in parts):
        parts.append("bounded samples")
    return ", ".join(parts)
