"""
HEEL — adversarial agent class (spec §3.1). The swarm-native capability-surface search.

v2 (Phase 3): the agent is now DECLARATIVE + MODEL-DRIVEN.
  * Probes are a single GENERIC criterion evaluator over OBSERVABLE affordance signals, so
    scenarios are addable WITHOUT code (incl. loaded from JSON) — `evaluate_criterion`.
  * A pluggable MODEL (`heel/model.py`) drives discovery (and could drive assessment). The
    default `StubModel` is deterministic and needs no API key (spec §11); an `AnthropicModel`
    swaps in behind `HEEL_MODEL=anthropic` for a real LLM control loop.

Safety spine (§10) unchanged: probes read only OBSERVABLE signals (control presence as revealed
by probing; enumerated properties) — never planted ground truth — and emit contained, canary-only
PoCs. Content/jailbreak handled by scenario `handoff` (never weaponized); true-vuln → appsec.
"""
from __future__ import annotations

from .contracts import (
    AbuseScenario,
    AbuseVector,
    AppliesWhen,
    ScenarioSource,
    Severity,
)
from .targets import PLAUSIBILITY_FLOOR


# --------------------------------------------------------------------------- #
# Generic declarative criterion evaluator (observable signals only)
# --------------------------------------------------------------------------- #
def evaluate_criterion(crit: dict, aff) -> bool:
    p = aff.properties
    if "semantic" in crit:
        from .semantic import semantic_match
        return semantic_match(crit["semantic"], aff)
    if "guard_absent" in crit:
        return (not aff.guard_present) == bool(crit["guard_absent"])
    if "prop" in crit and "equals" in crit:
        return p.get(crit["prop"]) == crit["equals"]
    if "prop" in crit and "in" in crit:
        return p.get(crit["prop"]) in crit["in"]
    if "prop" in crit and "exists" in crit:
        return (crit["prop"] in p) == bool(crit["exists"])
    if "prop_contains" in crit:
        k, s = crit["prop_contains"]
        return s in str(p.get(k, ""))
    if "prop_neq" in crit:
        a, b = crit["prop_neq"]
        return p.get(a) is not None and p.get(b) is not None and p.get(a) != p.get(b)
    if "all_of" in crit:
        return all(evaluate_criterion(c, aff) for c in crit["all_of"])
    if "any_of" in crit:
        return any(evaluate_criterion(c, aff) for c in crit["any_of"])
    if "not" in crit:
        return not evaluate_criterion(crit["not"], aff)
    return False


def estimate_reachability(aff) -> float:
    """Continuous plausibility estimate from observable PREREQUISITE DEPTH (DECISIONS D-010)."""
    p = aff.properties
    reach = 0.85 if not aff.guard_present else 0.6
    if p.get("client_reachable") is False:
        reach *= 0.18
    req = p.get("requires")
    if req:
        steps = max([int(t) for t in str(req).replace("-", " ").split() if t.isdigit()] or [3])
        reach *= 0.85 ** max(steps, 3)
    for k in ("auth_step", "verification", "payment", "depth"):
        if p.get(k):
            reach *= 0.7
    if p.get("documented") is False:
        reach = min(0.95, reach + 0.04)
    return round(max(0.05, min(0.95, reach)), 3)


def _vector(target, aff, scenario, vid, evidence) -> AbuseVector:
    reach = estimate_reachability(aff)
    sev = scenario.severity_model
    return AbuseVector(
        id=vid, scenario_id=scenario.id, category=scenario.category,
        reproduction={"strategy": scenario.probe_strategy, "steps": ["enumerate", "probe", "observe", "halt"],
                      "observed": evidence, "sample": "canary_only", "contained": True},
        severity=Severity(sev["likelihood"], sev["impact"], 0.2),
        reachability_score=reach, plausible=reach >= PLAUSIBILITY_FLOOR,
        recommended_control=scenario.recommended_control,
        estimated_exploitability_reduction=scenario.exploitability_reduction,
        handoff_to_appsec=(scenario.handoff == "appsec"),
        target_id=target.id, affordance_id=aff.id,
    )


def run_adversarial(target, scenarios: list[AbuseScenario], log, run_id: str, model=None) -> dict:
    from .model import get_model
    model = model or get_model()
    findings: dict[str, AbuseVector] = {}
    _rank: dict[str, tuple] = {}   # affordance_id -> (specificity, severity) of the kept finding
    handoffs: list[dict] = []
    fired: set[str] = set()
    probe_count = 0
    vid = 0

    for sc in scenarios:
        if sc.applies_when == AppliesWhen.HAS_AGENT_SURFACE and not target.has_agent_surface:
            continue  # category-10 cleanly yields nothing on a non-AI target
        kind = sc.target_affordance_pattern.get("kind")
        for aff in target.affordances:
            if kind != "*" and aff.kind != kind:
                continue
            probe_count += 1
            hit = evaluate_criterion(sc.success_criterion, aff)
            log("probe", {"scenario": sc.id, "affordance": aff.id, "fired": hit, "contained": True})
            if not hit:
                continue
            fired.add(aff.id)
            if sc.handoff == "model_redteam":   # pure jailbreak surface → handoff, never a finding
                handoffs.append({"affordance": aff.id, "handoff": "model_redteam",
                                 "reason": "pure model-jailbreak surface — out of HEEL's lane"})
                log("handoff", {"affordance": aff.id, "to": "model_redteam"})
                continue
            vid += 1
            v = _vector(target, aff, sc, f"av:{run_id}:{vid}", {"criterion": sc.success_criterion})
            # dedup rank = (specificity, severity): an EXACT prop match (100) beats a SPECIFIC semantic
            # topic match beats a GENERIC one — improving category attribution without an oracle.
            if "semantic" in sc.success_criterion:
                from .semantic import semantic_specificity
                rank = (semantic_specificity(sc.success_criterion["semantic"], aff), v.severity.score)
            else:
                rank = (100, v.severity.score)
            cur = findings.get(aff.id)
            if cur is None or rank > _rank.get(aff.id, (-1, -1)):
                findings[aff.id] = v
                _rank[aff.id] = rank
            log("finding", {"affordance": aff.id, "category": v.category.value, "severity": v.severity.label})

    discovered, extra = model.discover(target, fired, run_id, log)
    for v in extra:
        findings.setdefault(v.affordance_id, v)
    return {"findings": list(findings.values()), "handoffs": handoffs,
            "discovered_scenarios": discovered, "probe_count": probe_count, "model": model.name}


# --------------------------------------------------------------------------- #
# Discovery heuristic (used by StubModel; the LLM model reasons instead)
# --------------------------------------------------------------------------- #
_CONTROL_HINT_KEYS = ("protection", "check", "filter", "isolation", "guard", "logged", "allowlist", "limit")
_MISSING_VALUES = {"missing", "none", "false", False}


def heuristic_discover(target, fired, run_id, log):
    discovered, extra = [], []
    vid = 1000
    for aff in target.affordances:
        if aff.id in fired or aff.decoy:
            continue
        for k, val in aff.properties.items():
            if any(h in k for h in _CONTROL_HINT_KEYS) and isinstance(val, (str, bool)) and (val in _MISSING_VALUES):
                sc = AbuseScenario(
                    id=f"sc.discovered.{aff.id}", category=aff.category,
                    objective=f"Discovered: missing control '{k}' on {aff.kind} affordance",
                    target_affordance_pattern={"kind": aff.kind}, probe_strategy="discovered",
                    success_criterion={"prop": k, "equals": val},
                    severity_model={"likelihood": 0.5, "impact": 0.5},
                    source=ScenarioSource.DISCOVERED,
                    recommended_control="add the missing control indicated by the probe",
                    exploitability_reduction=0.7)
                discovered.append(sc)
                vid += 1
                extra.append(_vector(target, aff, sc, f"av:{run_id}:{vid}", {"obs": f"{k}={val} (discovered)"}))
                log("discovered_scenario", {"affordance": aff.id, "control": k})
                break
    return discovered, extra
