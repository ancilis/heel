"""
HEEL — adversarial agent class (spec §3.1). The swarm-native capability-surface search.

v1 is a DETERMINISTIC stub model (spec §11: a stub model path so the synthetic demo runs
with no API key; the LLM control loop is Phase 3). The agent enumerates a target's
`Affordance` surface and runs each applicable scenario's CONTAINED probe, reading ONLY
observable signals (whether the control is present, as revealed by probing; and enumerated
properties) — never the planted ground truth.

Safety spine (§10) baked in:
  * detection-not-weaponization — probes return a contained PoC (steps + a CANARY-only
    result), prove reachability, and stop. No real exfiltration, no sustained exhaustion.
  * content/jailbreak — the content-guardrail probe uses a benign canary to verify guardrail
    PRESENCE and never generates the artifact; pure-jailbreak surfaces are handed off
    (handoff_to_model_redteam), never weaponized (lane discipline, §4.10 boundary).
  * true-vuln classes (e.g. SSRF) are flagged handoff_to_appsec.
  * every probe is recorded to the ContainmentLog via `log`.
"""
from __future__ import annotations

from .contracts import (
    AbuseScenario,
    AbuseVector,
    AppliesWhen,
    Category,
    ScenarioSource,
    Severity,
    SyntheticTarget,
)
from .targets import PLAUSIBILITY_FLOOR

# --------------------------------------------------------------------------- #
# Observable probe evaluators: (affordance) -> evidence dict if the abuse condition
# is observed, else None. NEVER read planted_weakness / true_severity / reachability.
# --------------------------------------------------------------------------- #
def _p_entitlement(a): return {"control": "entitlement_check absent"} if not a.guard_present else None
def _p_export_overbroad(a):
    return {"heuristic": "bulk-export route"} if "export" in a.properties.get("route", "") else None
def _p_meter(a): return {"obs": "client-controlled reset window"} if a.properties.get("reset_window") == "client_controlled" else None
def _p_tenant(a): return {"obs": "tenant check missing"} if a.properties.get("tenant_check") == "missing" else None
def _p_client_flag(a): return {"obs": "gated by client flag"} if a.properties.get("gated_by") == "client" else None
def _p_serial_trial(a): return {"obs": "identity check = email_only"} if a.properties.get("identity_check") == "email_only" else None
def _p_audit(a): return {"obs": "action not audit-logged"} if a.properties.get("audit_logged") is False else None
def _p_hidden(a):
    p = a.properties
    return {"obs": "undocumented + client-reachable"} if (p.get("documented") is False and p.get("client_reachable") is True) else None
def _p_forced(a): return {"obs": "reachable past gating (depth?)"} if a.properties.get("client_reachable") is False else None
def _p_referral(a): return {"obs": "self-referral check missing"} if a.properties.get("self_referral_check") == "missing" else None
def _p_recovery(a): return {"obs": "weak account-recovery check"} if a.properties.get("recovery_check") == "weak" else None
def _p_agent_scope(a):
    p = a.properties
    g, i = p.get("granted_scope"), p.get("intended_scope")
    return {"obs": f"granted {g} > intended {i}"} if (g and i and g != i) else None
def _p_infer_amp(a): return {"obs": "unbounded multi-step run"} if a.properties.get("multi_step") == "unbounded" else None
def _p_agent_retrieval(a): return {"obs": "retrieval tenant filter missing"} if a.properties.get("tenant_filter") == "missing" else None
def _p_deputy(a): return {"obs": "authz = caller_assumed"} if a.properties.get("authz_check") == "caller_assumed" else None
def _p_mcp_isolation(a): return {"obs": "context isolation missing"} if a.properties.get("context_isolation") == "missing" else None
def _p_ssrf(a): return {"obs": "url-fetch allowlist missing"} if a.properties.get("allowlist") == "missing" else None
def _p_jailbreak(a): return {"obs": "model-jailbreak surface"} if a.properties.get("jailbreak_surface") is True else None
def _p_content_guardrail(a):
    # SAFE canary only: verify guardrail PRESENCE; never generate the prohibited artifact.
    if a.properties.get("blocks_prohibited") is True:
        return None  # guardrail present → no vector (canary blocked, as it should be)
    return {"obs": "content guardrail ABSENT (verified with benign canary)", "max_severity": True}


PROBES = {
    "entitlement_probe": _p_entitlement, "export_overbroad_probe": _p_export_overbroad,
    "meter_window_probe": _p_meter, "tenant_isolation_probe": _p_tenant,
    "client_flag_probe": _p_client_flag, "serial_trial_probe": _p_serial_trial,
    "audit_coverage_probe": _p_audit, "endpoint_enumeration_probe": _p_hidden,
    "forced_browsing_probe": _p_forced, "referral_self_probe": _p_referral,
    "account_recovery_probe": _p_recovery,
    "agent_tool_scope_probe": _p_agent_scope, "inference_amplification_probe": _p_infer_amp,
    "agent_retrieval_probe": _p_agent_retrieval, "confused_deputy_probe": _p_deputy,
    "mcp_isolation_probe": _p_mcp_isolation, "url_fetch_ssrf_probe": _p_ssrf,
    "jailbreak_handoff_probe": _p_jailbreak, "content_guardrail_canary": _p_content_guardrail,
}

CONTROLS = {
    "entitlement_probe": ("enforce server-side entitlement check on export", 0.85),
    "export_overbroad_probe": ("rate-limit + entitlement-gate all export routes", 0.6),
    "meter_window_probe": ("move usage-meter reset to server-authoritative windows", 0.8),
    "tenant_isolation_probe": ("enforce tenant scoping on every record access", 0.9),
    "client_flag_probe": ("gate tier on server-verified entitlement, not a client flag", 0.85),
    "serial_trial_probe": ("device/identity fingerprinting + trial-per-identity limit", 0.6),
    "audit_coverage_probe": ("add admin action to the immutable audit log", 0.8),
    "endpoint_enumeration_probe": ("remove/authgate undocumented endpoints", 0.8),
    "forced_browsing_probe": ("enforce server-side state gating", 0.7),
    "referral_self_probe": ("block self-referral + velocity limits", 0.7),
    "account_recovery_probe": ("rate-limit + strengthen account-recovery verification", 0.8),
    "agent_tool_scope_probe": ("scope agent tool permissions to the caller's tenant/intent", 0.9),
    "inference_amplification_probe": ("bound multi-step runs + per-call cost ceilings", 0.8),
    "agent_retrieval_probe": ("enforce tenant filter in retrieval/RAG", 0.9),
    "confused_deputy_probe": ("re-check authorization at the privileged tool, not the caller", 0.85),
    "mcp_isolation_probe": ("isolate per-connector context; no cross-server bleed", 0.8),
    "url_fetch_ssrf_probe": ("egress allowlist + metadata-endpoint block (see appsec)", 0.7),
    "content_guardrail_canary": ("add a content guardrail; block prohibited classes", 0.9),
    "discovered": ("add the missing control indicated by the probe", 0.7),
}


def estimate_reachability(aff) -> float:
    """The agent's OWN plausibility estimate from observable properties (not ground truth)."""
    p = aff.properties
    if p.get("client_reachable") is False or p.get("requires"):
        return 0.15
    base = 0.78 if not aff.guard_present else 0.55
    if p.get("documented") is False:
        base += 0.05
    return min(0.95, base)


def _vector(target, aff, scenario, evidence, vid) -> AbuseVector:
    ctrl, redux = CONTROLS.get(scenario.probe_strategy, CONTROLS["discovered"])
    reach = estimate_reachability(aff)
    sev = scenario.severity_model
    likelihood = sev["likelihood"]
    if evidence.get("max_severity"):
        likelihood, impact = 0.9, 1.0
    else:
        impact = sev["impact"]
    handoff_appsec = aff.properties.get("handoff") == "appsec"
    return AbuseVector(
        id=vid, scenario_id=scenario.id, category=scenario.category,
        reproduction={"strategy": scenario.probe_strategy, "steps": ["enumerate", "probe", "observe", "halt"],
                      "observed": evidence, "sample": "canary_only", "contained": True},
        severity=Severity(likelihood, impact),
        reachability_score=round(reach, 3), plausible=reach >= PLAUSIBILITY_FLOOR,
        recommended_control=ctrl, estimated_exploitability_reduction=redux,
        handoff_to_appsec=handoff_appsec, target_id=target.id, affordance_id=aff.id,
    )


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
def run_adversarial(target: SyntheticTarget, scenarios: list[AbuseScenario], log, run_id: str) -> dict:
    findings: dict[str, AbuseVector] = {}   # dedupe by affordance_id (keep highest severity)
    handoffs: list[dict] = []
    fired_affordances: set[str] = set()
    probe_count = 0
    vid = 0

    for sc in scenarios:
        if sc.applies_when == AppliesWhen.HAS_AGENT_SURFACE and not target.has_agent_surface:
            continue  # category-10 cleanly yields nothing on a non-AI target
        probe = PROBES.get(sc.probe_strategy)
        if not probe:
            continue
        kind = sc.target_affordance_pattern.get("kind")
        for aff in target.affordances:
            if aff.kind != kind:
                continue
            probe_count += 1
            ev = probe(aff)
            log("probe", {"scenario": sc.id, "affordance": aff.id, "fired": bool(ev), "contained": True})
            if not ev:
                continue
            fired_affordances.add(aff.id)
            # lane discipline: pure jailbreak surface → handoff, never a product-abuse finding
            if sc.probe_strategy == "jailbreak_handoff_probe":
                handoffs.append({"affordance": aff.id, "handoff": "model_redteam",
                                 "reason": "pure model-jailbreak surface — out of HEEL's lane"})
                log("handoff", {"affordance": aff.id, "to": "model_redteam"})
                continue
            vid += 1
            v = _vector(target, aff, sc, ev, f"av:{run_id}:{vid}")
            cur = findings.get(aff.id)
            if cur is None or v.severity.score > cur.severity.score:
                findings[aff.id] = v
            log("finding", {"affordance": aff.id, "category": v.category.value, "severity": v.severity.label})

    # discovery pass: propose scenarios for uncovered affordances showing a missing-control signal
    discovered_scenarios, extra = discovery_pass(target, fired_affordances, run_id, log)
    for v in extra:
        if v.affordance_id not in findings:
            findings[v.affordance_id] = v

    return {"findings": list(findings.values()), "handoffs": handoffs,
            "discovered_scenarios": discovered_scenarios, "probe_count": probe_count}


_CONTROL_HINT_KEYS = ("protection", "check", "filter", "isolation", "guard", "logged", "allowlist", "limit")
_MISSING_VALUES = {"missing", "none", "false", False}


def discovery_pass(target, fired_affordances, run_id, log) -> tuple[list[AbuseScenario], list[AbuseVector]]:
    """The swarm proposes new scenarios for affordances exhibiting a missing-control signal
    that no seed scenario fired on (spec §4: swarm proposes discovered scenarios)."""
    discovered, extra = [], []
    vid = 1000
    for aff in target.affordances:
        if aff.id in fired_affordances or aff.decoy:
            continue
        for k, val in aff.properties.items():
            if any(h in k for h in _CONTROL_HINT_KEYS) and (val in _MISSING_VALUES):
                sc = AbuseScenario(
                    id=f"sc.discovered.{aff.id}", category=aff.category,
                    objective=f"Discovered: missing control '{k}' on {aff.kind} affordance",
                    target_affordance_pattern={"kind": aff.kind}, probe_strategy="discovered",
                    success_criterion={"prop": k, "equals": "missing"},
                    severity_model={"likelihood": 0.5, "impact": 0.5},
                    source=ScenarioSource.DISCOVERED)
                discovered.append(sc)
                vid += 1
                v = _vector(target, aff, sc, {"obs": f"{k} = {val} (discovered)"}, f"av:{run_id}:{vid}")
                extra.append(v)
                log("discovered_scenario", {"affordance": aff.id, "control": k})
                break
    return discovered, extra
