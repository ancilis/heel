"""
HEEL — declarative motivation profiles for the opportunistic-human agent class (spec §3.2).

Defined INLINE (not learned from any telemetry). Axes: cost_sensitivity, risk_tolerance,
sophistication, tos_willingness — all in [0,1]. Operators add more as specs.
"""
from __future__ import annotations

from .contracts import MotivationProfile

DEFAULT_PROFILES: list[MotivationProfile] = [
    # high cost-sensitivity, low sophistication, moderate ToS-willingness
    MotivationProfile("cost_driven_cheapskate", cost_sensitivity=0.95, risk_tolerance=0.40,
                      sophistication=0.30, tos_willingness=0.55),
    # low sophistication, high willingness to bend rules
    MotivationProfile("low_sophistication_rule_bender", cost_sensitivity=0.70, risk_tolerance=0.55,
                      sophistication=0.20, tos_willingness=0.85),
    # high sophistication, comfortable with arbitrage/ToS edge
    MotivationProfile("sophisticated_arbitrageur", cost_sensitivity=0.80, risk_tolerance=0.75,
                      sophistication=0.95, tos_willingness=0.85),
]
PROFILE_BY_ID = {p.id: p for p in DEFAULT_PROFILES}
