"""
HEEL — affordance-chaining discovery (spec §3.1 "affordance chaining"). Phase 3.

The single-affordance adversarial probes miss abuse that requires COMBINING affordances
(e.g. a weak account-recovery + a session that isn't rotated → full account takeover). This
pass evaluates declarative CHAIN_PATTERNS over the affordance set and emits a chained vector
when every step's observable condition holds. Contained + canary-only like every probe.
"""
from __future__ import annotations

from .agents import evaluate_criterion
from .contracts import AbuseVector, Category, Severity

# A chain pattern: each step is (kind, criterion). If every step matches some affordance, the
# chain is reachable. `maps_to` lets a synthetic chain count against its planted ground-truth id.
CHAIN_PATTERNS = [
    {"id": "ato_chain", "category": Category.IDENTITY_ACCOUNT, "severity": (0.7, 0.8),
     "objective": "Account takeover by chaining weak recovery + non-rotated session",
     "steps": [{"kind": "auth_reset", "crit": {"prop": "recovery_check", "equals": "weak"}},
               {"kind": "session", "crit": {"prop": "session_rotation", "equals": "none"}}],
     "control": "rotate session + invalidate tokens on recovery; step-up auth", "maps_to": "ato_chain"},
    {"id": "exfil_chain", "category": Category.DATA_HARVESTING, "severity": (0.7, 0.8),
     "objective": "Bulk exfiltration by chaining tenant-bleed read + ungated export",
     "steps": [{"kind": "record", "crit": {"prop": "tenant_check", "equals": "missing"}},
               {"kind": "export", "crit": {"guard_absent": True}}],
     "control": "tenant-scope reads AND entitlement-gate exports", "maps_to": None},
]


def run_chaining(target, log, run_id: str) -> list[AbuseVector]:
    from .agents import estimate_reachability
    out, vid = [], 9000
    for pat in CHAIN_PATTERNS:
        matched = []
        for step in pat["steps"]:
            cand = next((a for a in target.affordances
                         if a.kind == step["kind"] and evaluate_criterion(step["crit"], a)), None)
            if cand is None:
                break
            matched.append(cand)
        if len(matched) != len(pat["steps"]):
            continue
        aid = pat["maps_to"] or ("chain:" + "+".join(m.id for m in matched))
        reach = round(min(estimate_reachability(m) for m in matched) * 0.8, 3)  # chains are deeper
        like, imp = pat["severity"]
        like = round(like * max(0.3, min(1.0, reach / 0.6)), 3)  # demote severity when the chain is less reachable
        vid += 1
        log("chain_discovered", {"pattern": pat["id"], "affordances": [m.id for m in matched]})
        out.append(AbuseVector(
            id=f"av:{run_id}:{vid}", scenario_id=f"chain.{pat['id']}", category=pat["category"],
            reproduction={"strategy": "affordance_chain", "chain": [m.id for m in matched],
                          "steps": [pat["objective"], "halt"], "sample": "canary_only", "contained": True},
            severity=Severity(like, imp, 0.25), reachability_score=reach, plausible=reach >= 0.25,
            recommended_control=pat["control"], estimated_exploitability_reduction=0.8,
            target_id=target.id, affordance_id=aid, notes=f"chained: {pat['id']}"))
    return out
