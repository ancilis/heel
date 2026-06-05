"""
HEEL — declarative abuse scenario library (spec §4). Seed set (the full library is Phase 3).

A scenario is a SPEC (addable without code): what surface it matches, an observable
(contained) probe strategy, and a success criterion that constitutes the abuse. The agent
(agents.py) executes the probe against a target's affordances; the probe reads only
OBSERVABLE signals (the control's presence/absence as revealed by probing, and enumerated
properties) — never the planted ground truth.

Seeded across categories 1–9 (universal core) + the §4.10 agent/MCP pack (applies_when =
has_agent_surface). Two scenarios are deliberately imperfect (one over-broad → a realistic
false positive; one forced-browsing → finds the degenerate, flagged implausible). The swarm
also DISCOVERS scenarios at runtime (agents.discovery_pass), tagged source=discovered.
"""
from __future__ import annotations

from .contracts import AbuseScenario, AppliesWhen, Category, ScenarioSource


def _s(id, cat, objective, kind, strategy, crit, like, imp, applies=AppliesWhen.ALWAYS, cat_match=None, cls=None):
    pat = {"kind": kind}
    if cat_match:
        pat["category"] = cat_match
    return AbuseScenario(
        id=id, category=cat, objective=objective, target_affordance_pattern=pat,
        probe_strategy=strategy, success_criterion=crit,
        severity_model={"likelihood": like, "impact": imp},
        classification_impact=cls, applies_when=applies, source=ScenarioSource.SEED,
        containment_limits={"max_probe_calls": 5, "backoff": True, "sample": "canary_only"},
    )


SEED_SCENARIOS: list[AbuseScenario] = [
    # ---- categories 1–9 (universal core) ----
    _s("sc.export.entitlement", Category.DATA_HARVESTING,
       "Bulk export reachable without an entitlement check",
       "export", "entitlement_probe", {"guard_absent": True}, 0.7, 0.8, cls="records"),
    _s("sc.export.overbroad", Category.DATA_HARVESTING,
       "Any bulk-export route is a potential over-extraction surface (over-broad heuristic)",
       "export", "export_overbroad_probe", {"route_contains": "export"}, 0.4, 0.6),
    _s("sc.meter.reset", Category.LICENSE_ENTITLEMENT,
       "Usage meter resettable via a client-controlled window",
       "meter", "meter_window_probe", {"prop": "reset_window", "equals": "client_controlled"}, 0.6, 0.6),
    _s("sc.record.tenant", Category.COMPLIANCE_BOUNDARY,
       "Cross-tenant record reachable (missing tenant isolation)",
       "record", "tenant_isolation_probe", {"prop": "tenant_check", "equals": "missing"}, 0.8, 0.9, cls="pii"),
    _s("sc.flag.tiergate", Category.UNINTENDED_ENDPOINTS,
       "Premium tier gated only by a client flag",
       "flag", "client_flag_probe", {"prop": "gated_by", "equals": "client"}, 0.6, 0.7),
    _s("sc.trial.serial", Category.LICENSE_ENTITLEMENT,
       "Serial-trial abuse via weak identity check",
       "trial", "serial_trial_probe", {"prop": "identity_check", "equals": "email_only"}, 0.5, 0.5),
    _s("sc.audit.coverage", Category.COMPLIANCE_BOUNDARY,
       "Admin action not written to the audit log",
       "admin_action", "audit_coverage_probe", {"prop": "audit_logged", "equals": False}, 0.6, 0.7),
    _s("sc.endpoint.hidden", Category.UNINTENDED_ENDPOINTS,
       "Undocumented endpoint reachable from the client",
       "endpoint", "endpoint_enumeration_probe", {"undocumented_and_reachable": True}, 0.5, 0.6),
    _s("sc.endpoint.forced", Category.UNINTENDED_ENDPOINTS,
       "Forced-browsing past gating (may be deep/unreachable — plausibility-weighted)",
       "endpoint", "forced_browsing_probe", {"client_reachable": False}, 0.3, 0.4),
    _s("sc.referral.selfdeal", Category.TRUST_ECONOMY,
       "Referral credits self-redeemable",
       "referral", "referral_self_probe", {"prop": "self_referral_check", "equals": "missing"}, 0.4, 0.5),
    _s("sc.identity.recovery", Category.IDENTITY_ACCOUNT,
       "Account-recovery / password-reset abuse via a weak recovery check",
       "auth_reset", "account_recovery_probe", {"prop": "recovery_check", "equals": "weak"}, 0.6, 0.7, cls="pii"),
    _s("sc.content.guardrail", Category.CONTENT_POLICY,
       "Verify content guardrail PRESENCE with a benign canary (never generate the artifact)",
       "content_guardrail", "content_guardrail_canary", {"blocks_prohibited": True}, 0.6, 0.9),
    # ---- category 10 (agent/MCP pack — conditional) ----
    _s("sc.agent.overscope", Category.AGENT_MCP_SURFACE,
       "Agent tool granted scope beyond intent (excessive agency)",
       "agent_tool", "agent_tool_scope_probe", {"scope_mismatch": True}, 0.8, 0.9,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.agent.costamp", Category.AGENT_MCP_SURFACE,
       "Cost amplification / denial-of-wallet on inference (cheap call → expensive run)",
       "agent_tool", "inference_amplification_probe", {"prop": "multi_step", "equals": "unbounded"}, 0.6, 0.7,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.agent.retrieval", Category.AGENT_MCP_SURFACE,
       "Cross-tenant retrieval reachable through the agent (RAG over-extraction)",
       "agent_tool", "agent_retrieval_probe", {"prop": "tenant_filter", "equals": "missing"}, 0.8, 0.9, cls="pii",
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.agent.deputy", Category.AGENT_MCP_SURFACE,
       "Confused-deputy: privileged tool invoked without proper authorization",
       "agent_tool", "confused_deputy_probe", {"prop": "authz_check", "equals": "caller_assumed"}, 0.6, 0.7,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.mcp.bleed", Category.AGENT_MCP_SURFACE,
       "MCP cross-server context bleed / transitive trust",
       "mcp_connector", "mcp_isolation_probe", {"prop": "context_isolation", "equals": "missing"}, 0.6, 0.6,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.func.ssrf", Category.FUNCTION_ABUSE,
       "URL-fetch SSRF / attack-proxy consequence (true-vuln class → handoff to appsec)",
       "agent_tool", "url_fetch_ssrf_probe", {"prop": "allowlist", "equals": "missing"}, 0.6, 0.7,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
    _s("sc.agent.jailbreak_handoff", Category.AGENT_MCP_SURFACE,
       "Pure model-jailbreak surface — out of HEEL's lane; flag handoff_to_model_redteam, never weaponize",
       "agent_tool", "jailbreak_handoff_probe", {"prop": "jailbreak_surface", "equals": True}, 0.0, 0.0,
       applies=AppliesWhen.HAS_AGENT_SURFACE),
]

SEED_BY_ID = {s.id: s for s in SEED_SCENARIOS}


def list_scenarios(filter_category: str | None = None, include_discovered: list | None = None) -> list[AbuseScenario]:
    out = list(SEED_SCENARIOS) + list(include_discovered or [])
    if filter_category:
        out = [s for s in out if s.category.value == filter_category]
    return out
