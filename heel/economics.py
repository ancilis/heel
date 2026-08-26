"""
Economic severity scoring for abuse findings.

This module is deliberately report-only. It never probes targets, never performs
network calls, and never changes AuthorizationScope state. It turns an existing
contained `AbuseVector` plus optional operator assumptions into a separate
business-impact estimate that can sit alongside, not replace, security severity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from typing import Any, Mapping


MONEY_FIELDS = (
    "revenue_leakage",
    "cloud_cost",
    "support_cost",
    "data_exposure_value",
    "trust_safety_cost",
    "compliance_cost",
)

_COMPONENT_UNIT_KEYS = {
    "revenue_leakage": ("unit_revenue_leakage", "unit_revenue_loss", "unit_lost_revenue", "unit_discount_value"),
    "cloud_cost": ("unit_cloud_cost", "unit_infra_cost", "unit_token_cost", "unit_compute_cost"),
    "support_cost": ("unit_support_cost", "support_ticket_cost"),
    "data_exposure_value": ("unit_data_exposure_value", "value_per_record", "record_value"),
    "trust_safety_cost": ("unit_trust_safety_cost", "trust_safety_review_cost"),
    "compliance_cost": ("unit_compliance_cost", "compliance_event_cost"),
}


@dataclass
class EconomicImpact:
    revenue_leakage: dict[str, Any] | None = None
    cloud_cost: dict[str, Any] | None = None
    support_cost: dict[str, Any] | None = None
    data_exposure_value: dict[str, Any] | None = None
    trust_safety_cost: dict[str, Any] | None = None
    compliance_cost: dict[str, Any] | None = None
    abuse_repeatability: float = 0.5
    time_to_detection: float = 0.5
    friction_cost_of_control: float = 0.4
    confidence: float = 0.35
    label: str = "low"
    score: float = 0.0
    estimated_monthly_range: dict[str, Any] | None = None
    assumptions: dict[str, Any] = field(default_factory=dict)
    unknowns: list[str] = field(default_factory=list)
    drivers: list[str] = field(default_factory=list)
    summary: str = ""
    currency: str = "USD"

    def to_dict(self) -> dict[str, Any]:
        return {
            "revenue_leakage": self.revenue_leakage,
            "cloud_cost": self.cloud_cost,
            "support_cost": self.support_cost,
            "data_exposure_value": self.data_exposure_value,
            "trust_safety_cost": self.trust_safety_cost,
            "compliance_cost": self.compliance_cost,
            "abuse_repeatability": self.abuse_repeatability,
            "time_to_detection": self.time_to_detection,
            "friction_cost_of_control": self.friction_cost_of_control,
            "confidence": self.confidence,
            "label": self.label,
            "score": self.score,
            "estimated_monthly_range": self.estimated_monthly_range,
            "assumptions": dict(self.assumptions),
            "unknowns": list(self.unknowns),
            "drivers": list(self.drivers),
            "summary": self.summary,
            "currency": self.currency,
        }


def load_assumptions(path: str | None = None) -> dict[str, Any] | None:
    """Load an economic assumptions JSON file.

    If `path` is omitted, `HEEL_ECONOMIC_ASSUMPTIONS` is honored. Missing input
    is not an error; the estimator will produce qualitative-only scores.
    """
    path = path or os.environ.get("HEEL_ECONOMIC_ASSUMPTIONS")
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("economic assumptions must be a JSON object")
    return data


def estimate_economic_impact(vector, product_model=None, assumptions=None) -> EconomicImpact:
    """Estimate business exposure for one finding without pretending precision.

    Dollar ranges are produced only when an operator supplies enough assumptions
    to calculate a range. Otherwise the output remains qualitative and explicitly
    lists unknowns.
    """
    all_assumptions = _merged_assumptions(product_model, assumptions)
    currency = str(all_assumptions.get("currency", "USD"))
    local, source = _assumptions_for(vector, all_assumptions)
    events = _first_range(local, "events_per_month", "monthly_events", "monthly_abuse_events")

    component_ranges: dict[str, tuple[float, float] | None] = {}
    for field_name in MONEY_FIELDS:
        component_ranges[field_name] = _component_range(field_name, local, events)

    total = None
    for rng in component_ranges.values():
        total = _add_ranges(total, rng)

    severity_score = _severity_score(vector)
    reachability = _float(_vget(vector, "reachability_score"), 0.5)
    repeatability = _repeatability(vector, local)
    time_to_detection = _time_to_detection(vector, local)
    friction = _friction(vector, local)
    qualitative = _qualitative_score(severity_score, reachability, repeatability, time_to_detection)
    score = _combined_score(total, qualitative)
    label = _label(score)

    assumptions_used = _used_assumptions(local, source, events)
    unknowns = _unknowns(local, events, component_ranges)
    confidence = _confidence(vector, local, total, unknowns)
    drivers = _drivers(vector, local, component_ranges, time_to_detection)
    money = _money_dict(total, currency) if total else None
    summary = _summary(money, label, drivers, unknowns, currency)

    return EconomicImpact(
        revenue_leakage=_money_dict(component_ranges["revenue_leakage"], currency),
        cloud_cost=_money_dict(component_ranges["cloud_cost"], currency),
        support_cost=_money_dict(component_ranges["support_cost"], currency),
        data_exposure_value=_money_dict(component_ranges["data_exposure_value"], currency),
        trust_safety_cost=_money_dict(component_ranges["trust_safety_cost"], currency),
        compliance_cost=_money_dict(component_ranges["compliance_cost"], currency),
        abuse_repeatability=round(repeatability, 3),
        time_to_detection=round(time_to_detection, 3),
        friction_cost_of_control=round(friction, 3),
        confidence=confidence,
        label=label,
        score=round(score, 3),
        estimated_monthly_range=money,
        assumptions=assumptions_used,
        unknowns=unknowns,
        drivers=drivers,
        summary=summary,
        currency=currency,
    )


def rank_by_economic_risk(findings):
    """Return findings sorted by economic impact while preserving the input items."""
    return sorted(findings, key=_economic_sort_key, reverse=True)


def recommend_control_bundle(findings, control_candidates):
    """Rank control candidates by economic risk reduction after friction cost.

    This intentionally does not pick the largest-reduction control blindly: a
    high-friction control can rank lower when its operator/customer cost exceeds
    the expected reduction.
    """
    enriched = [(f, _impact_dict(f)) for f in findings]
    total_value = sum(_risk_value(impact) for _, impact in enriched)
    ranked = []
    for candidate in control_candidates:
        c = dict(candidate)
        covered = [(f, i) for f, i in enriched if _candidate_matches(c, f)]
        covered_value = sum(_risk_value(i) for _, i in covered)
        reduction = _float(c.get("estimated_exploitability_reduction", c.get("reduction")), 0.0)
        friction_monthly = _friction_monthly(c, covered_value)
        gross = covered_value * reduction
        net = gross - friction_monthly
        c.update({
            "covered_findings": [_vget(f, "id", "") for f, _ in covered],
            "covered_monthly_risk": round(covered_value, 2),
            "gross_risk_reduction": round(gross, 2),
            "friction_cost_monthly": round(friction_monthly, 2),
            "net_monthly_value": round(net, 2),
        })
        ranked.append(c)
    ranked.sort(key=lambda c: (c["net_monthly_value"], c.get("gross_risk_reduction", 0.0)), reverse=True)
    return {
        "ranked_candidates": ranked,
        "total_monthly_risk": round(total_value, 2),
        "note": "Controls are ranked by estimated monthly risk reduction after friction; estimates are directional.",
    }


def _merged_assumptions(product_model, assumptions) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(product_model, Mapping):
        for key in ("economic_assumptions", "business_assumptions"):
            value = product_model.get(key)
            if isinstance(value, Mapping):
                out = _deep_merge(out, value)
    if isinstance(assumptions, Mapping):
        out = _deep_merge(out, assumptions)
    return out


def _assumptions_for(vector, assumptions: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    category = _category(vector)
    scenario_id = str(_vget(vector, "scenario_id", ""))
    affordance_id = str(_vget(vector, "affordance_id", ""))
    local: dict[str, Any] = {}
    source = ""
    for section, key in (
        ("defaults", "default"),
        ("categories", category),
        ("scenarios", scenario_id),
        ("affordances", affordance_id),
    ):
        section_value = assumptions.get(section)
        if section == "defaults" and isinstance(section_value, Mapping):
            local = _deep_merge(local, section_value)
            source = source or "defaults"
            continue
        if isinstance(section_value, Mapping) and key in section_value and isinstance(section_value[key], Mapping):
            local = _deep_merge(local, section_value[key])
            source = f"{section}.{key}"
    return local, source


def _component_range(field_name: str, local: Mapping[str, Any], events: tuple[float, float] | None):
    direct = _first_range(local, field_name, f"monthly_{field_name}")
    if direct:
        return direct
    if not events:
        return None
    unit = _first_range(local, *_COMPONENT_UNIT_KEYS[field_name])
    if unit is None and str(local.get("cost_kind", "")) == field_name:
        unit = _range(local.get("unit_cost"))
    if field_name == "compliance_cost" and unit is not None and local.get("compliance_event_probability") is not None:
        prob = _range(local.get("compliance_event_probability")) or (0.0, 0.0)
        return _mul_ranges(_mul_ranges(events, prob), unit)
    if unit is None:
        return None
    return _mul_ranges(events, unit)


def _used_assumptions(local: Mapping[str, Any], source: str, events) -> dict[str, Any]:
    used: dict[str, Any] = {}
    if source:
        used["source"] = source
    if events:
        used["events_per_month"] = _plain_range(events)
    for key, value in local.items():
        if key in {"driver", "confidence", "abuse_repeatability", "time_to_detection", "time_to_detection_days",
                   "friction_cost_of_control", "cost_kind"}:
            used[key] = value
        elif any(key in keys for keys in _COMPONENT_UNIT_KEYS.values()) or key.startswith("monthly_"):
            used[key] = value
    return used


def _unknowns(local, events, component_ranges) -> list[str]:
    unknowns = []
    if not local:
        unknowns.append("no economic assumptions matched this finding")
    if not events:
        unknowns.append("monthly abuse event volume")
    if not any(component_ranges.values()):
        unknowns.append("unit cost/value assumptions for monthly exposure")
    if "confidence" not in local:
        unknowns.append("operator confidence in economic assumptions")
    return unknowns


def _drivers(vector, local, component_ranges, time_to_detection) -> list[str]:
    drivers = []
    if local.get("driver"):
        drivers.append(str(local["driver"]))
    else:
        drivers.append(_default_driver(vector))
    for field_name, rng in component_ranges.items():
        if rng and field_name.replace("_", " ") not in drivers:
            drivers.append(field_name.replace("_", " "))
    if time_to_detection >= 0.7:
        drivers.append("slow time-to-detection")
    return drivers[:4]


def _summary(money, label, drivers, unknowns, currency):
    if money:
        return f"Estimated monthly abuse exposure: {_format_money(money['low'], currency)}-{_format_money(money['high'], currency)}, driven by {', '.join(drivers)}."
    return f"Economic severity: {label} (qualitative only; missing {', '.join(unknowns[:2])})."


def _repeatability(vector, local) -> float:
    if local.get("abuse_repeatability") is not None:
        return _clip(_float(local.get("abuse_repeatability"), 0.5))
    text = _vector_text(vector)
    if any(token in text for token in ("meter", "trial", "coupon", "promo", "referral", "seat", "token")):
        return 0.85
    if any(token in text for token in ("export", "record", "tenant", "agent")):
        return 0.7
    return 0.55


def _time_to_detection(vector, local) -> float:
    if local.get("time_to_detection") is not None:
        return _clip(_float(local.get("time_to_detection"), 0.5))
    days = _first_range(local, "time_to_detection_days", "detection_lag_days")
    if days:
        return _clip(_mid(days) / 30.0)
    text = _vector_text(vector)
    if "audit" in text or "logged" in text:
        return 0.35
    if any(token in text for token in ("coupon", "trial", "meter", "token", "export")):
        return 0.65
    return 0.5


def _friction(vector, local) -> float:
    if local.get("friction_cost_of_control") is not None:
        return _clip(_float(local.get("friction_cost_of_control"), 0.4))
    control = str(_vget(vector, "recommended_control", "")).lower()
    if any(token in control for token in ("manual", "human", "step-up")):
        return 0.75
    if any(token in control for token in ("rate", "limit", "challenge")):
        return 0.45
    if any(token in control for token in ("server", "entitlement", "meter")):
        return 0.3
    return 0.4


def _confidence(vector, local, total, unknowns) -> float:
    base = _float(local.get("confidence"), 0.55 if total else 0.35)
    uncertainty = _severity_uncertainty(vector)
    conf = base * max(0.25, 1.0 - uncertainty)
    if not total:
        conf = min(conf, 0.45)
    if unknowns:
        conf *= max(0.45, 1.0 - 0.12 * len(unknowns))
    if total and total[0] > 0 and total[1] / max(total[0], 1.0) > 10:
        conf *= 0.85
    return round(_clip(conf), 3)


def _qualitative_score(severity_score: float, reachability: float, repeatability: float, time_to_detection: float) -> float:
    score = severity_score * (0.55 + 0.45 * reachability)
    score *= (0.75 + 0.35 * repeatability)
    score *= (0.8 + 0.25 * time_to_detection)
    return _clip(score)


def _combined_score(total, qualitative: float) -> float:
    if not total:
        return qualitative
    high = total[1]
    if high >= 250_000:
        money_score = 0.9
    elif high >= 50_000:
        money_score = 0.72
    elif high >= 10_000:
        money_score = 0.56
    elif high >= 1_000:
        money_score = 0.36
    else:
        money_score = 0.16
    return _clip(0.7 * money_score + 0.3 * qualitative)


def _label(score: float) -> str:
    return "critical" if score >= 0.7 else "high" if score >= 0.45 else "medium" if score >= 0.25 else "low"


def _economic_sort_key(finding) -> tuple[float, float, float]:
    impact = _impact_dict(finding)
    rng = impact.get("estimated_monthly_range") or {}
    return (
        _float(impact.get("score"), 0.0),
        _float(rng.get("high"), 0.0),
        _float(impact.get("confidence"), 0.0),
    )


def _impact_dict(finding) -> dict[str, Any]:
    impact = _vget(finding, "economic_impact")
    if isinstance(impact, EconomicImpact):
        return impact.to_dict()
    if isinstance(impact, Mapping):
        return dict(impact)
    return estimate_economic_impact(finding).to_dict()


def _risk_value(impact: Mapping[str, Any]) -> float:
    rng = impact.get("estimated_monthly_range")
    conf = _float(impact.get("confidence"), 0.35)
    if isinstance(rng, Mapping):
        return _mid((_float(rng.get("low"), 0.0), _float(rng.get("high"), 0.0))) * conf
    return _float(impact.get("score"), 0.0) * 10_000 * conf


def _candidate_matches(candidate: Mapping[str, Any], finding) -> bool:
    for key, attr in (("affordance_ids", "affordance_id"), ("scenario_ids", "scenario_id"), ("categories", "category")):
        values = candidate.get(key)
        if values is None:
            continue
        if isinstance(values, str):
            values = [values]
        actual = _category(finding) if attr == "category" else str(_vget(finding, attr, ""))
        if actual not in {str(v) for v in values}:
            return False
    return True


def _friction_monthly(candidate: Mapping[str, Any], covered_value: float) -> float:
    for key in ("friction_cost_monthly", "monthly_friction_cost"):
        if candidate.get(key) is not None:
            return _float(candidate.get(key), 0.0)
    friction = candidate.get("friction_cost")
    if isinstance(friction, Mapping):
        if friction.get("monthly") is not None:
            return _float(friction.get("monthly"), 0.0)
        if friction.get("low") is not None or friction.get("high") is not None:
            return _mid((_float(friction.get("low"), 0.0), _float(friction.get("high"), 0.0)))
    normalized = candidate.get("friction_cost_of_control", friction)
    if isinstance(normalized, (int, float)):
        value = _float(normalized, 0.0)
        if 0.0 <= value <= 1.0:
            return covered_value * value
        return value
    return 0.0


def _default_driver(vector) -> str:
    text = _vector_text(vector)
    if "token" in text or "meter" in text:
        return "unmetered usage or cost amplification"
    if "coupon" in text or "promo" in text:
        return "promotion or discount leakage"
    if "export" in text or "record" in text:
        return "data exposure or bulk extraction"
    if "referral" in text or "review" in text:
        return "trust and safety operational load"
    return "repeatable product-abuse path"


def _vector_text(vector) -> str:
    fields = [_vget(vector, "id", ""), _vget(vector, "scenario_id", ""), _vget(vector, "affordance_id", ""),
              _vget(vector, "recommended_control", ""), _category(vector)]
    return " ".join(str(f).lower() for f in fields)


def _severity_score(vector) -> float:
    sev = _vget(vector, "severity", {})
    if isinstance(sev, Mapping):
        if sev.get("score") is not None:
            return _clip(_float(sev.get("score"), 0.0))
        return _clip(_float(sev.get("likelihood"), 0.0) * _float(sev.get("impact"), 0.0))
    if hasattr(sev, "score"):
        return _clip(_float(getattr(sev, "score"), 0.0))
    return 0.0


def _severity_uncertainty(vector) -> float:
    sev = _vget(vector, "severity", {})
    if isinstance(sev, Mapping):
        return _clip(_float(sev.get("uncertainty"), 0.2))
    return _clip(_float(getattr(sev, "uncertainty", 0.2), 0.2))


def _category(vector) -> str:
    cat = _vget(vector, "category", "")
    return str(getattr(cat, "value", cat))


def _vget(vector, key, default=None):
    if isinstance(vector, Mapping):
        return vector.get(key, default)
    return getattr(vector, key, default)


def _first_range(mapping: Mapping[str, Any], *keys: str):
    for key in keys:
        if key in mapping:
            rng = _range(mapping.get(key))
            if rng is not None:
                return rng
    return None


def _range(value) -> tuple[float, float] | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        if "low" in value or "high" in value:
            low = _float(value.get("low", value.get("high")), None)
            high = _float(value.get("high", value.get("low")), None)
            if low is None or high is None:
                return None
            return _ordered_range(low, high)
        if "monthly" in value:
            return _range(value.get("monthly"))
    if isinstance(value, (list, tuple)) and len(value) == 2:
        low = _float(value[0], None)
        high = _float(value[1], None)
        if low is None or high is None:
            return None
        return _ordered_range(low, high)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        return _ordered_range(number, number)
    return None


def _ordered_range(low: float, high: float) -> tuple[float, float]:
    low, high = max(0.0, low), max(0.0, high)
    return (low, high) if low <= high else (high, low)


def _mul_ranges(a, b) -> tuple[float, float]:
    return _ordered_range(a[0] * b[0], a[1] * b[1])


def _add_ranges(a, b):
    if b is None:
        return a
    if a is None:
        return b
    return (a[0] + b[0], a[1] + b[1])


def _money_dict(rng, currency: str):
    if rng is None:
        return None
    return {"low": round(rng[0], 2), "high": round(rng[1], 2), "currency": currency}


def _plain_range(rng):
    return {"low": round(rng[0], 4), "high": round(rng[1], 4)}


def _mid(rng) -> float:
    return (rng[0] + rng[1]) / 2.0


def _format_money(value: float, currency: str) -> str:
    prefix = "$" if currency == "USD" else f"{currency} "
    if value >= 1_000_000:
        return f"{prefix}{value / 1_000_000:.1f}m"
    if value >= 1_000:
        return f"{prefix}{value / 1_000:.0f}k"
    return f"{prefix}{value:.0f}"


def _float(value, default=0.0):
    try:
        if value is None or isinstance(value, bool):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _clip(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _deep_merge(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for key, value in b.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out
