"""
HEEL — held-out evaluation against INDEPENDENTLY-AUTHORED targets (the strongest honesty test).

The blind eval still used encodings HEEL's author wrote. These targets were authored by a separate
LLM swarm given only the abuse TAXONOMY and an output schema — never HEEL's scenarios or property
vocabulary (see docs/HELDOUT_PROVENANCE.md). They are frozen in heel/heldout/targets.json. So the
property names/values are genuinely held out, and HEEL's recall here is real detection accuracy with
NO author control over the encoding.

It reports recall both ways: EXACT-match scenarios (which key off specific property names + kinds)
vs the library WITH the SEMANTIC family (synonym generalization). The gap is the honest result —
exact matching barely generalizes; semantic matching recovers a fraction; neither is near 1.0.
"""
from __future__ import annotations

import json
import hashlib
import os
import random
from collections import Counter

from .agents import run_adversarial
from .backtest import score_target
from .blind_eval import _wilson
from .chaining import run_chaining
from .contracts import Affordance, Category, PlantedVector, Severity, SyntheticTarget
from .model import StubModel
from .scenarios import all_seed_scenarios

_DIR = os.path.join(os.path.dirname(__file__), "heldout")
FIXTURES = os.path.join(_DIR, "targets.json")            # DEV split (tuned on)
TEST_FIXTURES = os.path.join(_DIR, "test_targets.json")  # TEST split (frozen, never tuned on)


def _noop(*a):
    return None


def _build_target(p: dict) -> SyntheticTarget:
    affs, planted = [], []
    for a in p["affordances"]:
        cat = Category(a["category"])
        sv = a.get("severity") or {}
        tsev = Severity(round(float(sv.get("likelihood", 0.5)), 3), round(float(sv.get("impact", 0.5)), 3))
        reach = float(a.get("reachability", 0.7))
        decoy = bool(a.get("is_decoy"))
        wk = str(a.get("weakness", "weakness"))[:60]
        affs.append(Affordance(id=a["id"], kind=a["kind"], category=cat, properties=dict(a["properties"]),
                               guard_present=decoy, reachability=reach,
                               planted_weakness=None if decoy else wk, true_severity=tsev, decoy=decoy))
        if not decoy:
            planted.append(PlantedVector(id=f"pv:{p['id']}:{a['id']}", target_id=p["id"], category=cat,
                                         affordance_id=a["id"], weakness=wk, true_severity=tsev,
                                         reachable=reach >= 0.25))
    return SyntheticTarget(id=p["id"], kind=p.get("kind", "saas"),
                           has_agent_surface=bool(p.get("has_agent_surface")), affordances=affs,
                           planted_vectors=planted, description="held-out (independently LLM-authored)")


def _cluster_ci(rows, key_num, key_den, iters=2000):
    """Target-level (cluster) bootstrap CI — resample the TARGETS, not the weaknesses, because the
    weaknesses are nested in targets with strong heterogeneity (iid Wilson is ~45% too narrow)."""
    rng = random.Random(20260605)
    n = len(rows)
    if n < 2:
        return [None, None]
    ests = []
    for _ in range(iters):
        sample = [rows[rng.randrange(n)] for _ in range(n)]
        num = sum(r[key_num] for r in sample)
        den = sum(r[key_den] for r in sample)
        if den:
            ests.append(num / den)
    ests.sort()
    lo = ests[int(0.025 * len(ests))]
    hi = ests[int(0.975 * len(ests)) - 1]
    return [round(lo, 3), round(hi, 3)]


def _run(targets, semantic: bool) -> dict:
    scs = all_seed_scenarios(semantic=semantic)
    rows = []  # one per target, for cluster bootstrap
    cat_found, cat_attr, cat_plant = Counter(), Counter(), Counter()
    for t in targets:
        out = run_adversarial(t, scs, _noop, t.id, model=StubModel())
        ids = {f.affordance_id for f in out["findings"]}
        for v in run_chaining(t, _noop, t.id):
            if v.affordance_id not in ids:
                out["findings"].append(v)
        sc = score_target(t, out)
        rows.append({"tp": sc["true_positives"], "tp_attr": sc["attribution_true_positives"],
                     "plant": sc["reachable_planted"], "fp": sc["false_positives"]})
        found_cat = {f.affordance_id: f.category.value for f in out["findings"] if f.plausible}
        for pv in t.planted_vectors:
            if pv.reachable:
                cat_plant[pv.category.value] += 1
                if pv.affordance_id in found_cat:
                    cat_found[pv.category.value] += 1
                    if found_cat[pv.affordance_id] == pv.category.value:
                        cat_attr[pv.category.value] += 1
    tp = sum(r["tp"] for r in rows)
    tp_attr = sum(r["tp_attr"] for r in rows)
    plant = sum(r["plant"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    return {
        "recall": round(tp / plant, 3) if plant else 0.0,                       # localization recall
        "attribution_recall": round(tp_attr / plant, 3) if plant else 0.0,      # + correct category
        "found": tp, "attribution_found": tp_attr, "planted": plant, "fp": fp,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "wilson_ci95": _wilson(tp, plant),                                      # (iid; kept for reference)
        "recall_cluster_ci95": _cluster_ci(rows, "tp", "plant"),               # target-bootstrap (headline)
        "attribution_cluster_ci95": _cluster_ci(rows, "tp_attr", "plant"),
        "precision_cluster_ci95": _cluster_ci([{"tp": r["tp"], "tpfp": r["tp"] + r["fp"]} for r in rows], "tp", "tpfp"),
        "recall_by_category": {c: f"{cat_found[c]}/{cat_plant[c]}" for c in sorted(cat_plant)},
        "attribution_by_category": {c: f"{cat_attr[c]}/{cat_plant[c]}" for c in sorted(cat_plant)}}


def _eval_split(path: str) -> dict:
    raw = open(path, "rb").read()
    targets = [_build_target(p) for p in json.loads(raw)]
    n_planted = sum(1 for t in targets for pv in t.planted_vectors)
    n_reach = sum(1 for t in targets for pv in t.planted_vectors if pv.reachable)
    n_decoy = sum(1 for t in targets for a in t.affordances if a.decoy)
    return {"n_targets": len(targets), "total_planted": n_reach,
            "planted_all": n_planted, "n_below_reachability": n_planted - n_reach,  # currently 0 — the gate is a no-op
            "n_decoys": n_decoy, "sha256": hashlib.sha256(raw).hexdigest()[:16],
            "exact_match": _run(targets, False), "with_semantic": _run(targets, True)}


def heldout_eval() -> dict:
    dev = _eval_split(FIXTURES)
    out = {
        "provenance": "targets authored by an independent LLM swarm, blind to HEEL's probe vocabulary",
        "discipline": "DEV split was tuned on; TEST split is frozen + content-hashed and was never "
                      "inspected/tuned on (docs/HELDOUT_PROVENANCE.md) — the TEST number is the unbiased one. "
                      "Recall is reported two ways: LOCALIZATION (right affordance) and the stricter "
                      "ATTRIBUTION (right affordance AND category). CIs are target-level cluster bootstraps.",
        "dev": dev,
        # back-compat top-level = dev (existing callers/tests/UI)
        "n_targets": dev["n_targets"], "total_planted": dev["total_planted"],
        "exact_match": dev["exact_match"], "with_semantic": dev["with_semantic"],
    }
    if os.path.exists(TEST_FIXTURES):
        test = _eval_split(TEST_FIXTURES)
        out["test"] = test
        ts = test["with_semantic"]
        out["headline"] = (f"held-out TEST (unbiased, {test['total_planted']} weaknesses, sha {test['sha256']}): "
                           f"localization recall {ts['recall']} cluster-CI {ts['recall_cluster_ci95']}, "
                           f"ATTRIBUTION recall {ts['attribution_recall']} cluster-CI {ts['attribution_cluster_ci95']}, "
                           f"precision {ts['precision']} cluster-CI {ts['precision_cluster_ci95']}. "
                           f"exact-match {test['exact_match']['recall']}; DEV {dev['with_semantic']['recall']}. "
                           f"Not near 1.0 — the honest ceiling. (old headline kept below)")
        out["_headline_legacy"] = (f"held-out TEST recall (unbiased, {test['total_planted']} weaknesses authored "
                           f"blind to the tuner): exact {test['exact_match']['recall']} -> semantic "
                           f"{test['with_semantic']['recall']} (Wilson CI {test['with_semantic']['wilson_ci95']}) "
                           f"at precision {test['with_semantic']['precision']}. DEV recall {dev['with_semantic']['recall']}. "
                           f"Generalizes to vocabulary it never saw; not near 1.0 — the honest ceiling.")
    return out


def main():
    print(json.dumps(heldout_eval(), indent=1))


if __name__ == "__main__":
    main()
