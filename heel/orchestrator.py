"""
HEEL — swarm orchestrator (spec §7). HEEL owns this.

Spawns/monitors the agent run, aggregates traces, scores against planted ground truth,
and persists. v1 runs the adversarial class against a synthetic target under an enforced
scope; the opportunistic-human class and true thousand-agent fan-out are Phase 3. Every
action is recorded to the immutable ContainmentLog.
"""
from __future__ import annotations

import time
import uuid

from .agents import run_adversarial
from .agents_human import run_opportunistic
from .backtest import score_target
from .classify import enrich as classify_enrich
from .containment import ContainmentLog
from .contracts import CallerContext, RunResult
from .control import enrich_controls
from .profiles import DEFAULT_PROFILES
from .scenarios import list_scenarios
from .targets import get_target

DEFAULT_CLASSES = ["adversarial", "opportunistic"]


def run_abuse(scope, target_id: str, scenario_ids, caller: CallerContext, store,
              run_id: str | None = None, classify_enabled: bool = False,
              agent_classes: list | None = None) -> RunResult:
    run_id = run_id or ("run-" + uuid.uuid4().hex[:10])
    store.add_run(run_id, scope.scope_id, target_id, caller.caller_identity, "running", time.time())
    log = ContainmentLog(store, run_id, caller.caller_identity).logger()
    log("run_start", {"scope_id": scope.scope_id, "target": target_id,
                      "caller": caller.caller_identity, "limits": scope.rate_and_resource_limits})

    target = get_target(target_id)
    if target is None:
        store.set_run_status(run_id, "rejected", error="unknown target")
        log("reject", {"reason": "unknown target", "target": target_id})
        return RunResult(run_id, "rejected", caller, error="unknown target")

    scenarios = list_scenarios()
    if scenario_ids:
        scenarios = [s for s in scenarios if s.id in set(scenario_ids)]
    classes = agent_classes or DEFAULT_CLASSES

    # adversarial (programmatic) class — the bulk of the swarm
    output = run_adversarial(target, scenarios, log, run_id) if "adversarial" in classes else \
        {"findings": [], "handoffs": [], "discovered_scenarios": [], "probe_count": 0}
    by_aff = {f.affordance_id: f for f in output["findings"]}

    # opportunistic-human class — motivation-profiled gaming of normal affordances (§3.2)
    if "opportunistic" in classes:
        opp = run_opportunistic(target, DEFAULT_PROFILES, log, run_id)
        for f in opp["findings"]:
            if f.affordance_id not in by_aff:   # ADD what it uniquely games; keep adversarial's calibrated severities
                by_aff[f.affordance_id] = f
        output["opportunistic_profiles"] = opp["profiles_used"]

    # affordance-chaining discovery — multi-step abuse the single-affordance classes miss
    if "adversarial" in classes:
        from .chaining import run_chaining
        for f in run_chaining(target, log, run_id):
            if f.affordance_id not in by_aff:
                by_aff[f.affordance_id] = f

    output["findings"] = list(by_aff.values())
    enrich_controls(output["findings"])
    classify_enrich(output["findings"], enabled=classify_enabled)   # optional annotation (off by default)
    score = score_target(target, output)
    score["agent_classes"] = classes

    for v in output["findings"]:
        store.add_finding(run_id, v)
    store.set_run_status(run_id, "complete", coverage=score)
    log("run_complete", {"n_findings": len(output["findings"]),
                         "coverage": score.get("coverage"), "fp_rate": score.get("false_positive_rate")})

    return RunResult(run_id, "complete", caller, findings=output["findings"], coverage=score)
