"""
HEEL — blind-target evaluation harness. Phase 3, red-team-hardened.

Runs the library against many procedurally-generated blind targets (heel/blind.py) whose planted
weaknesses use encodings authored independently of the seed probes, and aggregates an honest
detection DISTRIBUTION. Red-team corrections (EVAL §7):
  * recall is reported alongside the MEASURED encoding-overlap (the independent variable that bounds
    it) and labelled a stated LOWER BOUND — it is not presented as emergent detection skill.
  * a WILSON score interval is reported on the pooled found/planted proportion (the right model for
    a binomial), not a normal-z on a mean-of-ratios.
  * per-probe FALSE-POSITIVE attribution makes clear which probe(s) carry the precision number.
This is also the §7 fan-out: targets run concurrently via a thread pool (GIL-bound with the stub
model; with real LLM agents threads overlap network-bound work — see the honest wording below).
"""
from __future__ import annotations

import concurrent.futures
import math
import statistics
from collections import Counter

from .agents import run_adversarial
from .backtest import score_target
from .blind import generate_blind_target, measure_encoding_overlap
from .chaining import run_chaining
from .contracts import SyntheticTarget
from .model import StubModel
from .scenarios import all_seed_scenarios


def _noop(*a):
    return None


def _eval_one(seed: int) -> dict:
    t = generate_blind_target(seed)
    assert isinstance(t, SyntheticTarget) and t.id.startswith("blind-")  # synthetic-only invariant
    out = run_adversarial(t, all_seed_scenarios(), _noop, f"blind{seed}", model=StubModel())
    ids = {f.affordance_id for f in out["findings"]}
    for v in run_chaining(t, _noop, f"blind{seed}"):
        if v.affordance_id not in ids:
            out["findings"].append(v)
    sc = score_target(t, out)
    tp, fp = sc["true_positives"], sc["false_positives"]
    return {"seed": seed, "recall": sc["coverage"], "fp_rate": sc["false_positive_rate"],
            "precision": (tp / (tp + fp)) if (tp + fp) else None, "tp": tp, "fp": fp,
            "fn": sc["false_negatives"], "reachable": sc["reachable_planted"],
            "has_agent": t.has_agent_surface, "cat10_findings": sc["category10_findings"],
            "fp_scenarios": sc["false_positive_scenarios"]}


def _wilson(k, n, z=1.96):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z / d * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round(c - h, 3), round(c + h, 3)]


def blind_eval(n: int = 40, workers: int = 8) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        rows = list(ex.map(_eval_one, range(1, n + 1)))
    precs = [r["precision"] for r in rows if r["precision"] is not None]
    fps = [r["fp_rate"] for r in rows]
    non_ai = [r for r in rows if not r["has_agent"]]
    cat10_clean = sum(1 for r in non_ai if r["cat10_findings"] == 0)
    tot_found = sum(r["tp"] for r in rows)
    tot_plant = sum(r["reachable"] for r in rows)
    tot_fp = sum(r["fp"] for r in rows)
    fp_by_probe = Counter(s for r in rows for s in r["fp_scenarios"])
    overlap = measure_encoding_overlap()
    return {
        "n_targets": n, "workers": workers,
        "fan_out": f"{n} synthetic targets scored concurrently via a thread pool "
                   f"(GIL-bound, deterministic stub; real-LLM path overlaps network-bound work)",
        "encoding_overlap": overlap,  # the INDEPENDENT VARIABLE that bounds recall
        "real_recall_pooled": round(tot_found / tot_plant, 3) if tot_plant else None,
        "real_recall_wilson_ci95": _wilson(tot_found, tot_plant),
        "real_recall_is": "a stated LOWER BOUND ≈ the measured encoding-overlap; rises only as the "
                          "library covers more of the encoding vocabulary (it cannot be gamed by "
                          "writing probes against known plants). A defensible external claim needs "
                          "independently-authored / held-out scenarios.",
        "real_precision_pooled": round(tot_found / (tot_found + tot_fp), 3) if (tot_found + tot_fp) else None,
        "real_precision_wilson_ci95": _wilson(tot_found, tot_found + tot_fp),
        "false_positive_rate_mean": round(statistics.mean(fps), 3) if fps else None,
        "false_positives_by_probe": dict(fp_by_probe),  # transparency: which probe carries the FPs
        "total_found": tot_found, "total_planted": tot_plant, "total_missed": sum(r["fn"] for r in rows),
        "non_ai_targets": len(non_ai), "category10_clean_on_non_ai": f"{cat10_clean}/{len(non_ai)}",
    }
