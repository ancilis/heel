"""
Abuse regression tests.

A regression turns a contained HEEL finding into a reusable, non-weaponized test for a product abuse
control. Re-runs go through the same HeelServer execution path as ordinary runs: signed scope
required, target allowlist enforced, canary-only findings, no scope mutation surface, and immutable
containment logging.
"""
from __future__ import annotations

import hashlib
import os
import time

from .containment import ContainmentLog
from .scenarios import list_scenarios

EXPECTED_STATUSES = {"blocked", "still_reachable"}


class RegressionError(ValueError):
    """Raised when a regression cannot be created or exported."""


def _scenario_by_id(scenario_id: str):
    for scenario in list_scenarios():
        if scenario.id == scenario_id:
            return scenario
    return None


def _affordance_pattern_from_vector(vector: dict) -> dict:
    pattern = {"kind": "*"}
    try:
        from .targets import get_target

        target = get_target(vector.get("target_id", ""))
        aff = next((a for a in (target.affordances if target else []) if a.id == vector.get("affordance_id")), None)
        if aff:
            pattern["kind"] = aff.kind
    except Exception:
        pass
    pattern.update({
        "target_id": vector.get("target_id", ""),
        "affordance_id": vector.get("affordance_id", ""),
    })
    return pattern


def _regression_id(run_id: str, vector_id: str, name: str) -> str:
    digest = hashlib.sha1(f"{run_id}:{vector_id}:{name}".encode()).hexdigest()[:12]
    return f"reg-{digest}"


def add_regression_from_finding(store, run_id: str, vector_id: str, name: str,
                                expected_status: str = "blocked", now: float | None = None) -> dict:
    """Create a reusable regression spec from a previously stored finding.

    The stored regression intentionally excludes reproduction steps. It preserves the declarative
    scenario criterion and the safety metadata needed to re-run the same control check.
    """
    if expected_status not in EXPECTED_STATUSES:
        raise RegressionError("expected_status must be blocked or still_reachable")
    vector = store.find_vector(vector_id, run_id=run_id)
    if not vector:
        raise RegressionError(f"unknown vector_id '{vector_id}' for run '{run_id}'")
    scenario = _scenario_by_id(vector.get("scenario_id", ""))
    if not vector.get("scenario_id"):
        raise RegressionError(f"vector '{vector_id}' has no scenario_id")

    created_at = now if now is not None else time.time()
    reproduction = vector.get("reproduction") or {}
    pattern = (
        dict(scenario.target_affordance_pattern) if scenario else _affordance_pattern_from_vector(vector)
    )
    pattern.setdefault("target_id", vector.get("target_id", ""))
    pattern.setdefault("affordance_id", vector.get("affordance_id", ""))
    success_criterion = dict(scenario.success_criterion) if scenario else {"observed": reproduction.get("observed", {})}
    regression = {
        "regression_id": _regression_id(run_id, vector_id, name),
        "name": name,
        "original_vector_id": vector_id,
        "scenario_id": vector["scenario_id"],
        "target_affordance_pattern": pattern,
        "success_criterion": success_criterion,
        "recommended_control": vector.get("recommended_control") or (scenario.recommended_control if scenario else ""),
        "expected_status": expected_status,
        "created_at": created_at,
        "source_run_id": run_id,
        "safety_flags": {
            "scope_required": True,
            "canary_only": reproduction.get("sample") == "canary_only",
            "contained": bool(reproduction.get("contained")),
            "no_scope_widening": True,
            "handoff_to_appsec": bool(vector.get("handoff_to_appsec")),
            "handoff_to_model_redteam": bool(vector.get("handoff_to_model_redteam")),
        },
    }
    store.add_regression(regression)
    return regression


def _classes_for(regression: dict) -> list[str]:
    scenario_id = regression.get("scenario_id", "")
    if scenario_id.startswith("opportunistic."):
        return ["opportunistic"]
    return ["adversarial"]


def _scenario_ids_for(regression: dict):
    scenario_id = regression.get("scenario_id", "")
    if scenario_id.startswith("opportunistic.") or scenario_id.startswith("chain:"):
        return None
    return [scenario_id]


def _matching_findings(regression: dict, findings: list[dict]) -> list[dict]:
    scenario_id = regression.get("scenario_id")
    matches = [f for f in findings if f.get("scenario_id") == scenario_id and f.get("plausible", True)]
    affordance_id = (regression.get("target_affordance_pattern") or {}).get("affordance_id")
    exact = [f for f in matches if f.get("affordance_id") == affordance_id]
    return exact or matches


def _evidence_summary(regression: dict, current_status: str, matches: list[dict]) -> str:
    scenario_id = regression["scenario_id"]
    affordance_id = regression["target_affordance_pattern"].get("affordance_id", "<pattern>")
    if current_status == "still_reachable":
        first = matches[0]
        return (
            f"Current canary-only finding {first['id']} matched regression scenario {scenario_id} "
            f"on affordance {first.get('affordance_id', affordance_id)}; reproduction details are omitted."
        )
    if current_status == "blocked":
        return (
            f"No canary-only finding matched regression scenario {scenario_id} on affordance pattern "
            f"{affordance_id}; recommended control may be present."
        )
    return f"Regression scenario {scenario_id} did not complete conclusively; inspect the run status and containment log."


def run_regressions(store, server, scope_id: str, target: str, caller: str,
                    regression_ids: list[str] | None = None) -> list[dict]:
    """Run stored regressions against a target through the normal scoped HEEL run path."""
    wanted = set(regression_ids or [])
    regressions = [r for r in store.list_regressions() if not wanted or r["regression_id"] in wanted]
    results = []
    for regression in regressions:
        args = {
            "scope_id": scope_id,
            "target": target,
            "agent_classes": _classes_for(regression),
        }
        scenario_ids = _scenario_ids_for(regression)
        if scenario_ids:
            args["scenario_ids"] = scenario_ids
        run = server.heel_run(args, caller)
        run_id = run["run_id"]
        row = store.get_run(run_id)
        findings = server.heel_get_findings({"run_id": run_id}, caller)["findings"]
        matches = _matching_findings(regression, findings)
        if not row or row["status"] != "complete":
            current_status = "inconclusive"
            control_likely = "unknown"
        elif matches:
            current_status = "still_reachable"
            control_likely = "absent"
        else:
            current_status = "blocked"
            control_likely = "present"
        result = {
            "regression_id": regression["regression_id"],
            "name": regression["name"],
            "source_run_id": regression["source_run_id"],
            "original_vector_id": regression["original_vector_id"],
            "scenario_id": regression["scenario_id"],
            "scope_id": scope_id,
            "target": target,
            "run_id": run_id,
            "previously_reachable": True,
            "current_status": current_status,
            "control_likely": control_likely,
            "expected_status": regression["expected_status"],
            "matches_expected": current_status == regression["expected_status"],
            "evidence_summary": _evidence_summary(regression, current_status, matches),
            "created_at": time.time(),
            "safety_flags": dict(regression["safety_flags"]),
        }
        ContainmentLog(store, run_id, caller).append(
            "regression_result",
            {
                "regression_id": regression["regression_id"],
                "name": regression["name"],
                "current_status": current_status,
                "expected_status": regression["expected_status"],
                "scope_id": scope_id,
                "target": target,
                "canary_only": True,
            },
        )
        store.add_regression_result(result)
        results.append(result)
    return results


def export_regressions(store) -> dict:
    return {
        "regressions": store.list_regressions(),
        "results": store.list_regression_results(),
    }


def resolve_target_argument(target_arg: str) -> str:
    """Resolve `heel regress run --target` as either a target id or a ProductModel JSON path."""
    if os.path.isfile(target_arg) and target_arg.lower().endswith(".json"):
        from .importers import load_product_model, target_from_product_model
        from .targets import register_imported_target

        target = register_imported_target(target_from_product_model(load_product_model(target_arg)))
        return target.id
    return target_arg
