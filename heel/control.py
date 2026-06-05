"""
HEEL — control proposal + search (spec §7/§8). HEEL owns this.

For each vector, propose a RANKED set of candidate controls by estimated exploitability
reduction (the §7 "small search for the control that closes it"). v1 ranks the agent's
recommended control against a per-category control bank; a Phase-4 version would re-simulate
each candidate against the affordance to measure the reduction empirically.
"""
from __future__ import annotations

from .contracts import Category

# per-category candidate controls (control, estimated_exploitability_reduction)
CONTROL_BANK: dict[Category, list[tuple[str, float]]] = {
    Category.LICENSE_ENTITLEMENT: [
        ("server-authoritative entitlement + metering", 0.85),
        ("rate/velocity limits + device-identity binding", 0.7),
        ("anomaly detection on usage patterns", 0.5)],
    Category.DATA_HARVESTING: [
        ("entitlement-gate + per-tenant rate limits on bulk reads/exports", 0.85),
        ("row-level tenant scoping on every query", 0.9),
        ("export size caps + audit + step-up auth", 0.6)],
    Category.UNINTENDED_ENDPOINTS: [
        ("remove/auth-gate undocumented endpoints", 0.85),
        ("server-side state-machine gating (no forced browsing)", 0.75),
        ("deny-by-default routing + allowlist", 0.7)],
    Category.COMPLIANCE_BOUNDARY: [
        ("enforce tenant/residency scoping + retention", 0.9),
        ("complete the audit-log coverage for the action", 0.8),
        ("consent/authorization gate", 0.6)],
    Category.TRUST_ECONOMY: [
        ("self-dealing + collusion + velocity controls", 0.7),
        ("review/rating provenance + weighting", 0.5)],
    Category.IDENTITY_ACCOUNT: [
        ("strengthen recovery verification + rate limits", 0.8),
        ("device/session binding + anomaly checks", 0.7)],
    Category.AGENT_MCP_SURFACE: [
        ("scope agent tool permissions to caller intent/tenant", 0.9),
        ("re-check authorization at the privileged tool (no confused deputy)", 0.85),
        ("bound multi-step runs + per-call cost ceilings", 0.8),
        ("per-connector context isolation", 0.8)],
    Category.FUNCTION_ABUSE: [
        ("egress allowlist + metadata-endpoint block (coordinate appsec)", 0.7),
        ("per-call resource ceilings + back-off", 0.7)],
    Category.INTEGRATION_EXTENSIBILITY: [
        ("webhook replay protection (nonce + timestamp) + SSRF allowlist", 0.8),
        ("OAuth scope minimization + key rotation", 0.7)],
    Category.CONTENT_POLICY: [
        ("add a content guardrail blocking prohibited classes", 0.9)],
}


def enrich_controls(findings) -> None:
    for v in findings:
        if not v.recommended_control:
            best = control_search_for(v.category, v.recommended_control)
            if best:
                v.recommended_control = best[0]["control"]
                v.estimated_exploitability_reduction = best[0]["estimated_exploitability_reduction"]
        if v.estimated_exploitability_reduction is None:
            v.estimated_exploitability_reduction = 0.6


def control_search_for(category, agents_control: str | None):
    cands = []
    if agents_control:
        cands.append({"control": agents_control, "estimated_exploitability_reduction": None, "source": "agent"})
    for c, r in CONTROL_BANK.get(category if isinstance(category, Category) else Category(category), []):
        cands.append({"control": c, "estimated_exploitability_reduction": r, "source": "bank"})
    cands.sort(key=lambda d: (d["estimated_exploitability_reduction"] or 0.0), reverse=True)
    return cands


def propose_control(vector: dict) -> dict:
    """MCP `heel_propose_control` — a RANKED set of candidate controls by exploitability reduction."""
    cat = vector.get("category")
    ranked = control_search_for(cat, vector.get("recommended_control"))
    return {
        "vector_id": vector.get("id"),
        "recommended_control": vector.get("recommended_control"),
        "estimated_exploitability_reduction": vector.get("estimated_exploitability_reduction"),
        "ranked_candidates": ranked,
        "handoff_to_appsec": vector.get("handoff_to_appsec", False),
        "handoff_to_model_redteam": vector.get("handoff_to_model_redteam", False),
        "note": "Product/business-logic controls. True-vuln or pure-jailbreak items are handed off.",
    }
