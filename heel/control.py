"""
HEEL — control proposal (spec §8). HEEL owns this.

Each AbuseVector already carries a recommended control + estimated exploitability reduction
from the agent (agents.CONTROLS). This module is the place a Phase-3 control SEARCH would run
(propose several controls per vector, rank by estimated exploitability reduction). For v1 it
normalizes the recommended control and exposes `propose_control(vector)` for the MCP tool.
"""
from __future__ import annotations


def enrich_controls(findings) -> None:
    for v in findings:
        if not v.recommended_control:
            v.recommended_control = "scope/limit the affordance; add the missing control"
        if v.estimated_exploitability_reduction is None:
            v.estimated_exploitability_reduction = 0.6


def propose_control(vector: dict) -> dict:
    """MCP `heel_propose_control` — recommended control + estimated exploitability reduction."""
    return {
        "vector_id": vector.get("id"),
        "recommended_control": vector.get("recommended_control"),
        "estimated_exploitability_reduction": vector.get("estimated_exploitability_reduction"),
        "handoff_to_appsec": vector.get("handoff_to_appsec", False),
        "handoff_to_model_redteam": vector.get("handoff_to_model_redteam", False),
        "note": "Product/business-logic control. True-vuln or pure-jailbreak items are handed off, not closed here.",
    }
