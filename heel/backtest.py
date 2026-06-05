"""
HEEL — planted-vector coverage backtest (spec §5). The falsifiable spine / acceptance test.

Scores discovered vectors against a synthetic target's planted ground truth:
  * coverage = fraction of REACHABLE planted vectors rediscovered by a PLAUSIBLE finding
    (reachability-weighted, so unreachable/implausible findings are flagged not counted).
  * false_positive_rate = plausible findings that hit a non-planted (hardened/decoy)
    affordance / all plausible findings. (A tool that flags everything is useless.)
  * severity_calibration = rank correlation between HEEL's assigned severity and the
    planted true severity, over true positives.
  * category-10-on-non-AI = number of agent/MCP findings on a target with no agent surface
    (must be 0 — proves category 10 is optional).
Handoff items (model-redteam / appsec) are reported but not scored as product-abuse findings.
"""
from __future__ import annotations

import math
from collections import defaultdict

from .agents import estimate_reachability
from .contracts import Category, SyntheticTarget


def _avg_ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def _spearman(xs, ys):
    if len(xs) < 2:
        return None
    rx, ry = _avg_ranks(xs), _avg_ranks(ys)
    mx, my = sum(rx) / len(rx), sum(ry) / len(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    dy = math.sqrt(sum((b - my) ** 2 for b in ry))
    return round(num / (dx * dy), 3) if dx and dy else None


def score_target(target: SyntheticTarget, agent_output: dict) -> dict:
    findings = agent_output["findings"]
    planted = target.planted_vectors
    planted_affordances = {pv.affordance_id for pv in planted}
    reachable = [pv for pv in planted if pv.reachable]

    plausible = [f for f in findings if f.plausible]
    implausible = [f for f in findings if not f.plausible]
    found_aff = {f.affordance_id for f in plausible}

    tp = [pv for pv in reachable if pv.affordance_id in found_aff]
    fn = [pv for pv in reachable if pv.affordance_id not in found_aff]
    # FP accounting (red-team-hardened): a chain is a legitimate compound discovery ONLY if all its
    # legs are genuinely-vulnerable (no hardened decoy). A chain that touches a decoy is a real FALSE
    # ALARM — the blanket "chain:"-prefix exclusion was unsound and laundered such FPs.
    decoy_ids = {a.id for a in target.affordances if a.decoy}

    def _is_chain(f):
        return (f.reproduction or {}).get("strategy") == "affordance_chain"

    def _legs(f):
        return (f.reproduction or {}).get("chain", [])
    fp, compound = [], []
    for f in plausible:
        if f.affordance_id in planted_affordances:
            continue  # TP-eligible (counted via found_aff)
        if _is_chain(f):
            (fp if any(l in decoy_ids for l in _legs(f)) else compound).append(f)
        else:
            fp.append(f)  # single finding on a hardened/decoy affordance

    cov = len(tp) / len(reachable) if reachable else None
    # reachability-weighted coverage — LOAD-BEARING: every reachable planted vector is weighted by
    # the agent's per-affordance reachability ESTIMATE (continuous, depth-based), found or missed.
    find_by_aff = {f.affordance_id: f for f in plausible}
    aff_by_id = {a.id: a for a in target.affordances}

    def reach_est(pv):
        if pv.affordance_id in find_by_aff:
            return find_by_aff[pv.affordance_id].reachability_score
        a = aff_by_id.get(pv.affordance_id)
        return estimate_reachability(a) if a else 0.5
    w_num = sum(reach_est(pv) for pv in tp)
    w_den = sum(reach_est(pv) for pv in reachable)
    cov_w = round(w_num / w_den, 3) if w_den else None

    fp_rate = round(len(fp) / len(plausible), 3) if plausible else 0.0

    # severity calibration over true positives
    pred_sev, true_sev = [], []
    pv_by_aff = {pv.affordance_id: pv for pv in planted}
    for pv in tp:
        pred_sev.append(find_by_aff[pv.affordance_id].severity.score)
        true_sev.append(pv_by_aff[pv.affordance_id].true_severity.score)
    calibration = _spearman(pred_sev, true_sev)

    # per-category coverage
    by_cat = defaultdict(lambda: [0, 0])  # [found, total] over reachable planted
    for pv in reachable:
        by_cat[pv.category.value][1] += 1
        if pv.affordance_id in found_aff:
            by_cat[pv.category.value][0] += 1
    cat_cov = {c: {"found": v[0], "total": v[1]} for c, v in by_cat.items()}

    cat10_findings = [f for f in plausible if f.category == Category.AGENT_MCP_SURFACE]
    opportunistic = [f for f in findings if (f.reproduction or {}).get("class") == "opportunistic_human"]

    return {
        "target": target.id, "kind": target.kind, "has_agent_surface": target.has_agent_surface,
        "metric_kind": "self_consistency",
        "caveat": ("self-consistency / wiring backtest on a synthetic target whose planted weaknesses "
                   "and the seed probes were authored together; NOT a real-target detection-accuracy "
                   "number. Trustworthy real-target evaluation needs blind targets + held-out scenarios."),
        "reachable_planted": len(reachable),
        "true_positives": len(tp), "false_negatives": len(fn), "false_positives": len(fp),
        "coverage": round(cov, 3) if cov is not None else None,
        "coverage_reachability_weighted": cov_w,
        "false_positive_rate": fp_rate,
        "severity_calibration": calibration,
        "implausible_flagged": len(implausible),
        "category_coverage": cat_cov,
        "category10_findings": len(cat10_findings),
        "category10_clean_on_non_ai": (target.has_agent_surface or len(cat10_findings) == 0),
        "opportunistic_findings": len(opportunistic),
        "opportunistic_affordances": [f.affordance_id for f in opportunistic],
        "compound_chain_findings": len(compound),
        "missed": [{"affordance": pv.affordance_id, "category": pv.category.value, "weakness": pv.weakness} for pv in fn],
        "false_positive_affordances": [f.affordance_id for f in fp],
        "false_positive_scenarios": [f.scenario_id for f in fp],
        "discovered_scenarios": [s.id for s in agent_output["discovered_scenarios"]],
        "handoffs": agent_output["handoffs"],
        "n_findings": len(findings), "n_plausible": len(plausible),
    }
