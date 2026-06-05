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
from .backtest import score_target
from .classify import enrich as classify_enrich
from .containment import ContainmentLog
from .contracts import CallerContext, RunResult
from .control import enrich_controls
from .scenarios import list_scenarios
from .targets import get_target


def run_abuse(scope, target_id: str, scenario_ids, caller: CallerContext, store,
              run_id: str | None = None, classify_enabled: bool = False) -> RunResult:
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

    output = run_adversarial(target, scenarios, log, run_id)
    enrich_controls(output["findings"])
    classify_enrich(output["findings"], enabled=classify_enabled)   # optional annotation (off by default)
    score = score_target(target, output)

    for v in output["findings"]:
        store.add_finding(run_id, v)
    store.set_run_status(run_id, "complete", coverage=score)
    log("run_complete", {"n_findings": len(output["findings"]),
                         "coverage": score.get("coverage"), "fp_rate": score.get("false_positive_rate")})

    return RunResult(run_id, "complete", caller, findings=output["findings"], coverage=score)
