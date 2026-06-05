"""
HEEL — blind-target generator (red-team-driven; closes the circularity, EVAL §7).

The synthetic-target coverage backtest is a SELF-CONSISTENCY check: the seed probes and the
planted weaknesses were authored together. The red-team's prescription for a REAL detection-
accuracy metric: author the planted weakness and the probe's observable INDEPENDENTLY.

This generator does exactly that. Each weakness type has multiple ENCODINGS — different surface
vocabularies a real product might use for the same flaw. Only some encodings happen to match a
seed scenario's observable; the others are genuine blind spots. The generator picks encodings at
RANDOM (it does not know which the library covers), and decoys share property names with vulnerable
affordances but carry safe values (some trip over-broad heuristics → real false positives). Running
the library against many such targets yields an honest recall/precision DISTRIBUTION, not 1.0.
"""
from __future__ import annotations

import random

from .contracts import Affordance, Category, PlantedVector, Severity, SyntheticTarget

C = Category

# weakness -> list of encodings; an encoding = (kind, props, guard_absent).
# The FIRST encoding of most weaknesses matches a seed scenario (detectable); the rest use synonym
# vocabularies the library does NOT key off (genuine blind spots). The generator does not use this
# knowledge — detection emerges only from running the real scenarios.
WEAKNESSES = [
    ("tenant_bleed", C.COMPLIANCE_BOUNDARY, [
        ("record", {"tenant_check": "missing"}, False),
        ("record", {"tenant_scope": "shared"}, False),
        ("record", {"isolation": "off"}, False)]),
    ("export_ungated", C.DATA_HARVESTING, [
        ("export", {"route": "/api/export"}, True),
        ("report", {"route": "/api/report"}, True),
        ("export", {"route": "/api/dump"}, False)]),
    ("meter_gaming", C.LICENSE_ENTITLEMENT, [
        ("meter", {"reset_window": "client_controlled"}, False),
        ("meter", {"reset": "user_settable"}, False),
        ("counter", {"window": "browser"}, False)]),
    ("tier_bypass", C.UNINTENDED_ENDPOINTS, [
        ("flag", {"gated_by": "client"}, False),
        ("flag", {"enforcement": "clientside"}, False),
        ("toggle", {"trust": "browser"}, False)]),
    ("audit_gap", C.COMPLIANCE_BOUNDARY, [
        ("admin_action", {"audit_logged": False}, False),
        ("admin_action", {"logging": "off"}, False),
        ("privileged_op", {"recorded": "no"}, False)]),
    ("trial_serial", C.LICENSE_ENTITLEMENT, [
        ("trial", {"identity_check": "email_only"}, False),
        ("trial", {"identity": "email"}, False),
        ("signup", {"dedupe": "off"}, False)]),
    ("hidden_endpoint", C.UNINTENDED_ENDPOINTS, [
        ("endpoint", {"documented": False, "client_reachable": True}, False),
        ("endpoint", {"listed": "no", "reachable": "yes"}, False),
        ("route", {"internal": True, "exposed": True}, False)]),
    # agent / MCP weaknesses (only planted when the target has an agent surface)
    ("agent_overscope", C.AGENT_MCP_SURFACE, [
        ("agent_tool", {"granted_scope": "all", "intended_scope": "own"}, False),
        ("agent_tool", {"scope": "broad"}, False),
        ("agent_tool", {"permissions": "wide"}, False)], True),
    ("retrieval_bleed", C.AGENT_MCP_SURFACE, [
        ("agent_tool", {"tenant_filter": "missing"}, False),
        ("agent_tool", {"rag_scope": "global"}, False),
        ("agent_tool", {"corpus": "all_tenants"}, False)], True),
    ("ssrf", C.FUNCTION_ABUSE, [
        ("agent_tool", {"allowlist": "missing", "handoff": "appsec"}, False),
        ("agent_tool", {"egress": "open"}, False),
        ("agent_tool", {"fetch": "any_url"}, False)], True),
]

# decoys: hardened affordances on the BOUNDARY of each probe's failure mode (red-team-hardened so
# precision is not carried by a single over-broad rule). Several legitimately-gated export routes
# exercise the over-broad substring probe; the rest test that precise probes require the UNSAFE value.
DECOYS = [
    ("record", {"tenant_check": "enforced"}, True),
    ("meter", {"reset_window": "server"}, True),
    ("export", {"route": "/api/billing/export"}, True),     # gated, but the over-broad probe trips
    ("export", {"route": "/api/audit/export"}, True),       # ditto — FP is a category, not n=1
    ("export", {"route": "/reports/export"}, True),
    ("admin_action", {"audit_logged": True}, True),
    ("flag", {"gated_by": "server"}, True),
    ("agent_tool", {"granted_scope": "all", "intended_scope": "all"}, True),  # boundary for prop_neq
]


def measure_encoding_overlap() -> dict:
    """The library's measured coverage of the encoding vocabulary — the INDEPENDENT VARIABLE that
    bounds blind recall (red-team fix). Runs the real library against each catalog encoding."""
    from .agents import run_adversarial
    from .model import StubModel
    from .scenarios import all_seed_scenarios
    scs = all_seed_scenarios()
    total = matched = 0
    for w in WEAKNESSES:
        wid, cat, encs = w[0], w[1], w[2]
        for idx, (kind, props, ga) in enumerate(encs):
            total += 1
            aff = Affordance(id=f"enc.{wid}.{idx}", kind=kind, category=cat, properties=dict(props),
                             guard_present=not ga, reachability=0.8, planted_weakness=wid, true_severity=Severity(0.5, 0.5))
            t = SyntheticTarget(id="probe", kind="ai_agent", has_agent_surface=True, affordances=[aff], planted_vectors=[])
            out = run_adversarial(t, scs, lambda *a: None, "probe", model=StubModel())
            if any(f.affordance_id == aff.id for f in out["findings"]):
                matched += 1
    return {"encodings": total, "matchable": matched, "overlap": round(matched / total, 3)}


def generate_blind_target(seed: int) -> SyntheticTarget:
    rng = random.Random(f"blind:{seed}")
    has_agent = rng.random() < 0.5
    affs, planted = [], []
    i = 0
    pool = [w for w in WEAKNESSES if (len(w) < 4 or has_agent)]
    n_weak = rng.randint(5, 9)
    for _ in range(n_weak):
        w = rng.choice(pool)
        wid, cat, encodings = w[0], w[1], w[2]
        kind, props, guard_absent = rng.choice(encodings)
        i += 1
        sev = Severity(round(rng.uniform(0.4, 0.85), 2), round(rng.uniform(0.4, 0.9), 2))
        reach = round(rng.uniform(0.35, 0.92), 3)
        aff = Affordance(id=f"b{seed}.{wid}.{i}", kind=kind, category=cat, properties=dict(props),
                         guard_present=not guard_absent, reachability=reach, planted_weakness=wid,
                         true_severity=sev)
        affs.append(aff)
        planted.append(PlantedVector(id=f"pv:b{seed}:{aff.id}", target_id=f"blind-{seed}", category=cat,
                                     affordance_id=aff.id, weakness=wid, true_severity=sev,
                                     reachable=reach >= 0.25))
    for _ in range(rng.randint(2, 4)):
        kind, props, _ = rng.choice(DECOYS)
        i += 1
        affs.append(Affordance(id=f"b{seed}.decoy.{i}", kind=kind, category=C.DATA_HARVESTING,
                               properties=dict(props), guard_present=True, reachability=0.6, decoy=True))
    rng.shuffle(affs)
    return SyntheticTarget(id=f"blind-{seed}", kind="ai_agent" if has_agent else "saas",
                           has_agent_surface=has_agent, affordances=affs, planted_vectors=planted,
                           description="procedurally generated blind target (independent encodings)")
