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
import os
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


def _run(targets, semantic: bool) -> dict:
    scs = all_seed_scenarios(semantic=semantic)
    tp = plant = fp = 0
    cat_found, cat_plant = Counter(), Counter()
    for t in targets:
        out = run_adversarial(t, scs, _noop, t.id, model=StubModel())
        ids = {f.affordance_id for f in out["findings"]}
        for v in run_chaining(t, _noop, t.id):
            if v.affordance_id not in ids:
                out["findings"].append(v)
        sc = score_target(t, out)
        tp += sc["true_positives"]
        plant += sc["reachable_planted"]
        fp += sc["false_positives"]
        found_aff = {f.affordance_id for f in out["findings"]}
        for pv in t.planted_vectors:
            if pv.reachable:
                cat_plant[pv.category.value] += 1
                if pv.affordance_id in found_aff:
                    cat_found[pv.category.value] += 1
    return {"recall": round(tp / plant, 3) if plant else 0.0, "found": tp, "planted": plant, "fp": fp,
            "precision": round(tp / (tp + fp), 3) if (tp + fp) else None, "wilson_ci95": _wilson(tp, plant),
            "recall_by_category": {c: f"{cat_found[c]}/{cat_plant[c]}" for c in sorted(cat_plant)}}


def _eval_split(path: str) -> dict:
    with open(path) as fh:
        targets = [_build_target(p) for p in json.load(fh)]
    return {"n_targets": len(targets), "total_planted": _run(targets, True)["planted"],
            "exact_match": _run(targets, False), "with_semantic": _run(targets, True)}


def heldout_eval() -> dict:
    dev = _eval_split(FIXTURES)
    out = {
        "provenance": "targets authored by an independent LLM swarm, blind to HEEL's probe vocabulary",
        "discipline": "DEV split was tuned on; TEST split is frozen and was never inspected/tuned on "
                      "(see docs/HELDOUT_PROVENANCE.md) — the TEST number is the unbiased one.",
        "dev": dev,
        # back-compat top-level = dev (existing callers/tests/UI)
        "n_targets": dev["n_targets"], "total_planted": dev["total_planted"],
        "exact_match": dev["exact_match"], "with_semantic": dev["with_semantic"],
    }
    if os.path.exists(TEST_FIXTURES):
        test = _eval_split(TEST_FIXTURES)
        out["test"] = test
        out["headline"] = (f"held-out TEST recall (unbiased, {test['total_planted']} weaknesses authored "
                           f"blind to the tuner): exact {test['exact_match']['recall']} -> semantic "
                           f"{test['with_semantic']['recall']} (Wilson CI {test['with_semantic']['wilson_ci95']}) "
                           f"at precision {test['with_semantic']['precision']}. DEV recall {dev['with_semantic']['recall']}. "
                           f"Generalizes to vocabulary it never saw; not near 1.0 — the honest ceiling.")
    return out


def main():
    print(json.dumps(heldout_eval(), indent=1))


if __name__ == "__main__":
    main()
