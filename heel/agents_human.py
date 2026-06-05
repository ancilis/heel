"""
HEEL — opportunistic-human agent class (spec §3.2). Motivation-profiled, NOT learned.

Ordinary, motivated, non-expert users who GAME the product within its NORMAL affordances —
seat sharing, serial trials, finding the free path, region arbitrage, economy/referral gaming.
Conditioned by a declarative `MotivationProfile` (cost_sensitivity, risk_tolerance,
sophistication, tos_willingness); a gaming opportunity is pursued only if the profile's
sophistication and ToS-willingness clear that opportunity's bar — so different profiles surface
different vectors. This is why both classes matter: coupon-stacking is a genuine miss for the
programmatic adversarial class but is exactly what an opportunistic user does, so this class
closes it.

Contained + safe (§10.2): the "PoC" is the gaming recipe within normal affordances on canary
accounts — no real exfil, no real charges.
"""
from __future__ import annotations

from .contracts import AbuseVector, Category, Severity


def clip(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))

# gaming opportunity: (strategy, affordance kind, (observable prop, value), category,
#                      required sophistication, required tos_willingness, impact, control)
GAMING = [
    ("serial_trial", "trial", ("identity_check", "email_only"), Category.LICENSE_ENTITLEMENT,
     0.20, 0.45, 0.5, "device/identity fingerprinting + trial-per-identity limit"),
    ("referral_self_deal", "referral", ("self_referral_check", "missing"), Category.TRUST_ECONOMY,
     0.30, 0.55, 0.5, "block self-referral + velocity limits"),
    ("seat_sharing", "seat", ("sharing_detection", "none"), Category.LICENSE_ENTITLEMENT,
     0.20, 0.40, 0.5, "concurrent-session / device limits per seat"),
    ("region_arbitrage", "region", ("region_check", "ip_only"), Category.LICENSE_ENTITLEMENT,
     0.70, 0.50, 0.6, "verify billing region via payment instrument, not IP"),
    ("meter_gaming", "meter", ("reset_window", "client_controlled"), Category.LICENSE_ENTITLEMENT,
     0.45, 0.50, 0.55, "server-authoritative metering windows"),
    ("coupon_stacking", "endpoint", ("stackable", True), Category.LICENSE_ENTITLEMENT,
     0.30, 0.50, 0.5, "one promo per order; disallow coupon stacking"),
]


def _pursues(profile, req_soph, req_tos) -> bool:
    return (profile.sophistication >= req_soph and profile.tos_willingness >= req_tos
            and profile.cost_sensitivity >= 0.5)


def _likelihood(profile) -> float:
    # motivated users will game, but keep the estimate honest (not inflated)
    return clip(0.15 + 0.30 * profile.cost_sensitivity + 0.20 * profile.tos_willingness)


def run_opportunistic(target, profiles, log, run_id: str) -> dict:
    findings: dict[str, AbuseVector] = {}
    vid = 5000
    for strategy, kind, (prop, val), cat, req_soph, req_tos, impact, control in GAMING:
        for aff in target.affordances:
            if aff.kind != kind or aff.properties.get(prop) != val:
                continue
            pursuers = [p for p in profiles if _pursues(p, req_soph, req_tos)]
            log("opportunistic_probe", {"strategy": strategy, "affordance": aff.id,
                                        "pursued_by": [p.id for p in pursuers], "contained": True})
            if not pursuers:
                continue
            like = max(_likelihood(p) for p in pursuers)
            vid += 1
            v = AbuseVector(
                id=f"av:{run_id}:{vid}", scenario_id=f"opportunistic.{strategy}", category=cat,
                reproduction={"strategy": strategy, "class": "opportunistic_human",
                              "profiles": [p.id for p in pursuers],
                              "steps": ["use normal affordance", "repeat/abuse within ToS edge", "halt"],
                              "sample": "canary_only", "contained": True},
                severity=Severity(round(like, 3), impact, 0.25),
                reachability_score=0.8, plausible=True, recommended_control=control,
                estimated_exploitability_reduction=0.7, target_id=target.id, affordance_id=aff.id,
                notes=f"gamed by profiles: {', '.join(p.id for p in pursuers)}")
            cur = findings.get(aff.id)
            if cur is None or v.severity.score > cur.severity.score:
                findings[aff.id] = v
    return {"findings": list(findings.values()), "profiles_used": [p.id for p in profiles]}
