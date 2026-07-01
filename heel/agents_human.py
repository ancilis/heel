"""
HEEL — opportunistic-human agent class (spec §3.2).

This class models customer incentives, not criminal identity. Personas fire only when:
  * the persona's motivation tags match the rule,
  * its sophistication / patience / risk tolerance clear that rule's bar, and
  * the target exposes an observable affordance matching the rule criterion.

Contained + safe (§10.2): the PoC is a canary-only rehearsal of normal affordances. No real
exfiltration, credential abuse, payment abuse, spam, or resource exhaustion.
"""
from __future__ import annotations

from .agents import evaluate_criterion
from .contracts import AbuseVector, Category, Severity
from .profiles import AbusePersona, DEFAULT_PERSONAS, PersonaRule


def clip(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def _persona_can_pursue(persona: AbusePersona, rule: PersonaRule) -> bool:
    if rule.motivation_tags and not set(persona.motivation_tags).intersection(rule.motivation_tags):
        return False
    return (
        persona.sophistication >= rule.required_sophistication
        and persona.patience >= rule.required_patience
        and persona.risk_tolerance >= rule.required_risk_tolerance
    )


def _rule_matches(target, persona: AbusePersona, rule: PersonaRule, aff) -> bool:
    if rule.category == Category.AGENT_MCP_SURFACE and not target.has_agent_surface:
        return False
    if rule.affordance_kind != "*" and aff.kind != rule.affordance_kind:
        return False
    if "*" not in persona.target_affordance_types and aff.kind not in persona.target_affordance_types:
        return False
    if not _persona_can_pursue(persona, rule):
        return False
    return evaluate_criterion(rule.criterion, aff)


def _likelihood(persona: AbusePersona, rule: PersonaRule) -> float:
    # Honest, bounded motivation estimate. Personas explain incentive; they do not inflate severity.
    return round(clip(
        0.12
        + 0.30 * persona.motivation_intensity
        + 0.12 * persona.patience
        + 0.12 * persona.risk_tolerance
        + 0.08 * persona.sophistication
        - 0.05 * rule.required_sophistication
    ), 3)


def _evidence(persona: AbusePersona, rule: PersonaRule, aff) -> dict:
    return {
        "persona_id": persona.id,
        "motivation": persona.motivation,
        "why_this_customer_would_try_it": rule.why,
        "affordance_match": rule.affordance_match,
        "preferred_abuse_chain": rule.preferred_chain,
        "deterring_controls": list(persona.deterring_controls),
        "matched_affordance": aff.id,
        "matched_properties": dict(aff.properties),
    }


def _vector(target, aff, persona: AbusePersona, rule: PersonaRule, run_id: str, seq: int) -> AbuseVector:
    evidence = _evidence(persona, rule, aff)
    return AbuseVector(
        id=f"av:{run_id}:{5000 + seq}",
        scenario_id=f"persona.{persona.id}.{rule.id}",
        category=rule.category,
        reproduction={
            "strategy": rule.preferred_chain,
            "class": "opportunistic_human",
            "persona": {
                "id": persona.id,
                "motivation": persona.motivation,
                "sophistication": persona.sophistication,
                "patience": persona.patience,
                "risk_tolerance": persona.risk_tolerance,
            },
            "evidence": evidence,
            "persona_evidence": [evidence],
            "steps": [
                "select canary account or record",
                "exercise the normal product affordance once",
                "observe whether the canary control blocks it",
                "halt",
            ],
            "canary_rehearsal": list(persona.canary_rehearsal_examples),
            "sample": "canary_only",
            "contained": True,
        },
        severity=Severity(_likelihood(persona, rule), rule.impact, 0.25),
        reachability_score=round(clip(0.55 + 0.25 * persona.patience), 3),
        plausible=True,
        recommended_control=rule.recommended_control,
        estimated_exploitability_reduction=0.7,
        target_id=target.id,
        affordance_id=aff.id,
        notes=f"{persona.id}: {rule.why}",
    )


def _dedupe_evidence(items):
    out, seen = [], set()
    for item in items:
        key = (item["persona_id"], item["matched_affordance"], item["preferred_abuse_chain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def persona_rank(vector: AbuseVector) -> tuple[float, float, str]:
    """Ranking rule for persona-only collisions on one affordance: severity, reachability, stable id."""
    return (vector.severity.score, vector.reachability_score, vector.scenario_id)


def run_opportunistic(target, personas=None, log=None, run_id: str = "run") -> dict:
    personas = list(DEFAULT_PERSONAS if personas is None else personas)
    log = log or (lambda *a: None)
    findings: list[AbuseVector] = []
    evidence_by_affordance: dict[str, list[dict]] = {}
    seq = 0

    # Persona order and rule order are the prioritization model. Within one persona, rules are listed
    # from highest-value affordance to lower-value follow-on checks (for example export before record
    # enumeration for data_broker).
    for persona in personas:
        for rule in persona.rules:
            if not _persona_can_pursue(persona, rule):
                continue
            for aff in target.affordances:
                hit = _rule_matches(target, persona, rule, aff)
                log(
                    "opportunistic_probe",
                    {
                        "persona": persona.id,
                        "rule": rule.id,
                        "affordance": aff.id,
                        "fired": hit,
                        "contained": True,
                    },
                )
                if not hit:
                    continue
                seq += 1
                vector = _vector(target, aff, persona, rule, run_id, seq)
                findings.append(vector)
                evidence_by_affordance.setdefault(aff.id, []).append(vector.reproduction["evidence"])

    # Stable ranking for duplicate persona findings on the same affordance; keep all evidence in the
    # output side channel so the orchestrator can annotate an adversarial primary finding without
    # changing its severity/category/control.
    best_by_affordance: dict[str, AbuseVector] = {}
    for vector in findings:
        current = best_by_affordance.get(vector.affordance_id)
        if current is None or persona_rank(vector) > persona_rank(current):
            best_by_affordance[vector.affordance_id] = vector

    for vector in best_by_affordance.values():
        ev = _dedupe_evidence(evidence_by_affordance.get(vector.affordance_id, []))
        vector.reproduction["persona_evidence"] = ev

    return {
        "findings": list(best_by_affordance.values()),
        "personas_used": [p.id for p in personas],
        "profiles_used": [p.id for p in personas],  # backward-compatible output key
        "persona_evidence_by_affordance": {
            aff: _dedupe_evidence(items) for aff, items in evidence_by_affordance.items()
        },
        "merge_policy": "adversarial_primary_then_persona_evidence; persona_only_rank_by_severity_reachability",
    }
