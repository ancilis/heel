"""
HEEL — blind-target evaluation harness (the honest detection metric). Phase 3.

Runs the library against MANY procedurally-generated blind targets (heel/blind.py) whose planted
weaknesses use encodings authored INDEPENDENTLY of the seed probes, and aggregates a real
recall/precision/false-positive DISTRIBUTION with a 95% CI — the honest real-target detection
estimate the self-consistency backtest cannot give. It is also the §7 thousand-agent FAN-OUT:
targets run concurrently via a thread pool (with real LLM agents this overlaps network-bound work).
"""
from __future__ import annotations

import concurrent.futures
import math
import statistics

from .agents import run_adversarial
from .backtest import score_target
from .blind import generate_blind_target
from .chaining import run_chaining
from .model import StubModel
from .scenarios import all_seed_scenarios


def _noop(*a):
    return None


def _eval_one(seed: int) -> dict:
    t = generate_blind_target(seed)
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
            "has_agent": t.has_agent_surface, "cat10_findings": sc["category10_findings"]}


def _ci(xs):
    if len(xs) < 2:
        return [round(xs[0], 3), round(xs[0], 3)] if xs else [None, None]
    m, sem = statistics.mean(xs), statistics.pstdev(xs) / math.sqrt(len(xs))
    return [round(m - 1.96 * sem, 3), round(m + 1.96 * sem, 3)]


def blind_eval(n: int = 40, workers: int = 8) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        rows = list(ex.map(_eval_one, range(1, n + 1)))
    recalls = [r["recall"] for r in rows if r["recall"] is not None]
    precs = [r["precision"] for r in rows if r["precision"] is not None]
    fps = [r["fp_rate"] for r in rows]
    non_ai = [r for r in rows if not r["has_agent"]]
    cat10_clean = sum(1 for r in non_ai if r["cat10_findings"] == 0)
    return {
        "n_targets": n, "workers": workers, "fan_out": "concurrent.futures thread pool",
        "real_recall_mean": round(statistics.mean(recalls), 3) if recalls else None,
        "real_recall_ci95": _ci(recalls),
        "real_precision_mean": round(statistics.mean(precs), 3) if precs else None,
        "real_precision_ci95": _ci(precs),
        "false_positive_rate_mean": round(statistics.mean(fps), 3) if fps else None,
        "total_planted": sum(r["reachable"] for r in rows),
        "total_found": sum(r["tp"] for r in rows),
        "total_missed": sum(r["fn"] for r in rows),
        "non_ai_targets": len(non_ai),
        "category10_clean_on_non_ai": f"{cat10_clean}/{len(non_ai)}",
        "note": ("Honest real-target estimate: recall is FAR below the synthetic self-consistency "
                 "coverage because blind plants use encodings the library wasn't written against. "
                 "Recall rises as the library's encoding breadth grows."),
    }
