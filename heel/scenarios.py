"""
HEEL — declarative abuse scenario library (spec §4). Phase-3 full breadth.

Scenarios are pure SPECS (addable WITHOUT code): a surface pattern, a declarative
`success_criterion` interpreted by the generic evaluator (`agents.evaluate_criterion`), a
severity model, a recommended control, and an optional handoff. Seeded broadly across all ten
§4 categories; many scenarios match no affordance on the synthetic targets (they are there for
REAL targets) — that is breadth, not false positives. Extra scenarios can also be dropped into
`heel/scenarios_lib/*.json` and are merged at load time (`load_json_scenarios`).
"""
from __future__ import annotations

import glob
import json
import os

from .contracts import AbuseScenario, AppliesWhen, Category, ScenarioSource

_AGENT = AppliesWhen.HAS_AGENT_SURFACE


def _s(id, cat, objective, kind, crit, like, imp, control, redux=0.75, applies=AppliesWhen.ALWAYS,
       handoff="", cls=None):
    return AbuseScenario(
        id=id, category=cat, objective=objective, target_affordance_pattern={"kind": kind},
        probe_strategy=id.split(".", 1)[-1], success_criterion=crit,
        severity_model={"likelihood": like, "impact": imp}, classification_impact=cls,
        applies_when=applies, source=ScenarioSource.SEED, recommended_control=control,
        exploitability_reduction=redux, handoff=handoff,
        containment_limits={"max_probe_calls": 5, "backoff": True, "sample": "canary_only"})


SEED_SCENARIOS: list[AbuseScenario] = [
    # ---------- 4.1 license / entitlement ----------
    _s("sc.meter.reset", Category.LICENSE_ENTITLEMENT, "Usage meter resettable via a client-controlled window",
       "meter", {"prop": "reset_window", "equals": "client_controlled"}, 0.6, 0.6, "server-authoritative metering windows"),
    _s("sc.flag.tiergate", Category.UNINTENDED_ENDPOINTS, "Premium tier gated only by a client flag",
       "flag", {"prop": "gated_by", "equals": "client"}, 0.6, 0.7, "gate tier on server-verified entitlement, not a client flag"),
    _s("sc.trial.serial", Category.LICENSE_ENTITLEMENT, "Serial-trial abuse via weak identity check",
       "trial", {"prop": "identity_check", "equals": "email_only"}, 0.5, 0.5, "device/identity fingerprinting + trial-per-identity limit"),
    _s("sc.rate.circumvention", Category.LICENSE_ENTITLEMENT, "Rate/concurrency limit circumvention",
       "endpoint", {"prop": "rate_limit", "equals": "none"}, 0.5, 0.5, "server-side rate + concurrency limits"),
    # ---------- 4.2 data harvesting ----------
    _s("sc.export.entitlement", Category.DATA_HARVESTING, "Bulk export reachable without an entitlement check",
       "export", {"guard_absent": True}, 0.7, 0.8, "enforce server-side entitlement check on export", cls="records"),
    _s("sc.export.overbroad", Category.DATA_HARVESTING, "Any bulk-export route is a potential over-extraction surface",
       "export", {"prop_contains": ["route", "export"]}, 0.4, 0.6, "rate-limit + entitlement-gate all export routes", redux=0.6),
    _s("sc.record.tenant", Category.COMPLIANCE_BOUNDARY, "Cross-tenant record reachable (missing tenant isolation)",
       "record", {"prop": "tenant_check", "equals": "missing"}, 0.8, 0.9, "enforce tenant scoping on every record access", cls="pii"),
    _s("sc.data.enumeration", Category.DATA_HARVESTING, "Object/record enumeration via sequential ids",
       "record", {"prop": "id_scheme", "equals": "sequential"}, 0.5, 0.6, "use non-enumerable ids + per-tenant rate limits"),
    _s("sc.graphql.introspection", Category.DATA_HARVESTING, "GraphQL introspection exposes hidden capability",
       "endpoint", {"prop": "introspection", "equals": "enabled"}, 0.4, 0.5, "disable introspection in production"),
    # ---------- 4.3 unintended endpoints ----------
    _s("sc.endpoint.hidden", Category.UNINTENDED_ENDPOINTS, "Undocumented endpoint reachable from the client",
       "endpoint", {"all_of": [{"prop": "documented", "equals": False}, {"prop": "client_reachable", "equals": True}]},
       0.5, 0.6, "remove/auth-gate undocumented endpoints"),
    _s("sc.endpoint.forced", Category.UNINTENDED_ENDPOINTS, "Forced-browsing past gating (may be deep/unreachable)",
       "endpoint", {"prop": "client_reachable", "equals": False}, 0.3, 0.4, "enforce server-side state gating", redux=0.7),
    _s("sc.endpoint.massassign", Category.UNINTENDED_ENDPOINTS, "Mass-assignment unlocks gated fields",
       "endpoint", {"prop": "mass_assignment", "equals": "allowed"}, 0.5, 0.6, "allowlist writable fields"),
    # ---------- 4.4 function / capability abuse ----------
    _s("sc.func.ssrf", Category.FUNCTION_ABUSE, "URL-fetch SSRF / attack-proxy consequence (true-vuln → appsec)",
       "agent_tool", {"prop": "allowlist", "equals": "missing"}, 0.6, 0.7,
       "egress allowlist + metadata-endpoint block (see appsec)", applies=_AGENT, handoff="appsec"),
    _s("sc.func.botautomation", Category.FUNCTION_ABUSE, "Human-flow automated by bots (no challenge)",
       "endpoint", {"prop": "human_challenge", "equals": "none"}, 0.5, 0.5, "bot detection / challenge on sensitive flows"),
    # ---------- 4.5 content / policy ----------
    _s("sc.content.guardrail", Category.CONTENT_POLICY, "Verify content guardrail PRESENCE with a benign canary",
       "content_guardrail", {"prop": "blocks_prohibited", "equals": False}, 0.6, 0.9, "add a content guardrail; block prohibited classes"),
    # ---------- 4.6 identity / account ----------
    _s("sc.identity.recovery", Category.IDENTITY_ACCOUNT, "Account-recovery / password-reset abuse via a weak check",
       "auth_reset", {"prop": "recovery_check", "equals": "weak"}, 0.6, 0.7, "rate-limit + strengthen account-recovery verification", cls="pii"),
    _s("sc.identity.sybil", Category.IDENTITY_ACCOUNT, "Account farming / sybil creation",
       "signup", {"prop": "verification", "equals": "none"}, 0.5, 0.5, "proof-of-uniqueness + velocity limits on signup"),
    # ---------- 4.7 trust / economy ----------
    _s("sc.referral.selfdeal", Category.TRUST_ECONOMY, "Referral credits self-redeemable",
       "referral", {"prop": "self_referral_check", "equals": "missing"}, 0.4, 0.5, "block self-referral + velocity limits"),
    _s("sc.trust.reviewmanip", Category.TRUST_ECONOMY, "Review/rating manipulation",
       "review", {"prop": "provenance_check", "equals": "none"}, 0.4, 0.5, "verified-purchase weighting + provenance"),
    # ---------- 4.8 integration / extensibility ----------
    _s("sc.audit.coverage", Category.COMPLIANCE_BOUNDARY, "Admin action not written to the audit log",
       "admin_action", {"prop": "audit_logged", "equals": False}, 0.6, 0.7, "add admin action to the immutable audit log"),
    _s("sc.integration.oauth", Category.INTEGRATION_EXTENSIBILITY, "Over-broad OAuth scope grant",
       "oauth_app", {"prop": "scope", "equals": "all"}, 0.5, 0.6, "OAuth scope minimization + per-app review"),
    # NB: webhook replay is deliberately NOT seeded → the swarm must DISCOVER it (integration via discovery).
    # ---------- 4.9 compliance boundary ----------
    _s("sc.compliance.residency", Category.COMPLIANCE_BOUNDARY, "Data residency boundary crossable",
       "record", {"prop": "residency", "equals": "unpinned"}, 0.5, 0.7, "pin storage/processing region per tenant", cls="pii"),
    _s("sc.compliance.retention", Category.COMPLIANCE_BOUNDARY, "Deletion/retention circumvention",
       "record", {"prop": "hard_delete", "equals": "false"}, 0.4, 0.6, "enforce hard-delete + retention limits"),
    # ---------- 4.10 agent / MCP surface (conditional) ----------
    _s("sc.agent.overscope", Category.AGENT_MCP_SURFACE, "Agent tool granted scope beyond intent (excessive agency)",
       "agent_tool", {"prop_neq": ["granted_scope", "intended_scope"]}, 0.8, 0.9,
       "scope agent tool permissions to caller intent/tenant", applies=_AGENT),
    _s("sc.agent.costamp", Category.AGENT_MCP_SURFACE, "Cost amplification / denial-of-wallet on inference",
       "agent_tool", {"prop": "multi_step", "equals": "unbounded"}, 0.6, 0.7,
       "bound multi-step runs + per-call cost ceilings", applies=_AGENT),
    _s("sc.agent.retrieval", Category.AGENT_MCP_SURFACE, "Cross-tenant retrieval reachable through the agent",
       "agent_tool", {"prop": "tenant_filter", "equals": "missing"}, 0.8, 0.9,
       "enforce tenant filter in retrieval/RAG", applies=_AGENT, cls="pii"),
    _s("sc.agent.deputy", Category.AGENT_MCP_SURFACE, "Confused-deputy: privileged tool invoked without authorization",
       "agent_tool", {"prop": "authz_check", "equals": "caller_assumed"}, 0.6, 0.7,
       "re-check authorization at the privileged tool", applies=_AGENT),
    _s("sc.mcp.bleed", Category.AGENT_MCP_SURFACE, "MCP cross-server context bleed / transitive trust",
       "mcp_connector", {"prop": "context_isolation", "equals": "missing"}, 0.6, 0.6,
       "isolate per-connector context; no cross-server bleed", applies=_AGENT),
    _s("sc.mcp.toolpoison", Category.AGENT_MCP_SURFACE, "Tool poisoning / rug-pull via user-added connector metadata",
       "mcp_connector", {"prop": "tool_metadata_trusted", "equals": True}, 0.6, 0.7,
       "sandbox + review third-party tool metadata; pin versions", applies=_AGENT),
    _s("sc.agent.memory", Category.AGENT_MCP_SURFACE, "Persistent unauthorized behavior via memory/RAG over-extraction",
       "agent_tool", {"prop": "memory_scope", "equals": "cross_tenant"}, 0.7, 0.8,
       "scope agent memory/retrieval per tenant; expire", applies=_AGENT, cls="pii"),
    _s("sc.agent.indirect", Category.AGENT_MCP_SURFACE, "Indirect-injection-to-action (processed data triggers an action)",
       "agent_tool", {"prop": "acts_on_untrusted_content", "equals": True}, 0.7, 0.8,
       "treat processed content as untrusted; require human/authorization gate for actions", applies=_AGENT),
    _s("sc.agent.jailbreak_handoff", Category.AGENT_MCP_SURFACE, "Pure model-jailbreak surface — out of lane; hand off",
       "agent_tool", {"prop": "jailbreak_surface", "equals": True}, 0.0, 0.0,
       "(handed off to model red-team)", applies=_AGENT, handoff="model_redteam"),
]


# SEMANTIC scenarios — recognize weakness FAMILIES by topic+permissive vocabulary (heel/semantic.py),
# so the library generalizes to vocabularies it didn't author. Kind "*" matches any affordance kind.
def _sem(id, cat, objective, signal, like, imp, control, handoff="", kind="*", applies=AppliesWhen.ALWAYS):
    return AbuseScenario(
        id=id, category=cat, objective=objective, target_affordance_pattern={"kind": kind},
        probe_strategy="semantic", success_criterion={"semantic": signal},
        severity_model={"likelihood": like, "impact": imp}, applies_when=applies,
        source=ScenarioSource.SEED, recommended_control=control, exploitability_reduction=0.7, handoff=handoff)


SEMANTIC_SCENARIOS = [
    _sem("sc.sem.tenant", Category.COMPLIANCE_BOUNDARY, "Tenant isolation absent (any vocabulary)", "tenant_isolation", 0.8, 0.9, "enforce per-tenant scoping"),
    _sem("sc.sem.export", Category.DATA_HARVESTING, "Ungated bulk export/scrape (any vocabulary)", "bulk_export", 0.6, 0.7, "entitlement-gate + rate-limit exports"),
    _sem("sc.sem.meter", Category.LICENSE_ENTITLEMENT, "Client-controllable metering (any vocabulary)", "meter_reset", 0.6, 0.6, "server-authoritative metering"),
    _sem("sc.sem.tier", Category.UNINTENDED_ENDPOINTS, "Client-trusted tier gate (any vocabulary)", "tier_gate", 0.6, 0.7, "server-verified entitlement"),
    _sem("sc.sem.audit", Category.COMPLIANCE_BOUNDARY, "Audit-log gap (any vocabulary)", "audit_gap", 0.6, 0.7, "complete audit coverage"),
    _sem("sc.sem.recovery", Category.IDENTITY_ACCOUNT, "Weak account recovery (any vocabulary)", "recovery_weak", 0.6, 0.7, "strengthen + rate-limit recovery"),
    _sem("sc.sem.agentscope", Category.AGENT_MCP_SURFACE, "Over-scoped agent tool (any vocabulary)", "agent_scope", 0.8, 0.9, "scope tool perms to caller", applies=_AGENT),
    _sem("sc.sem.retrieval", Category.AGENT_MCP_SURFACE, "Cross-tenant retrieval (any vocabulary)", "retrieval_tenant", 0.8, 0.9, "tenant-filter retrieval", applies=_AGENT),
    _sem("sc.sem.ssrf", Category.FUNCTION_ABUSE, "SSRF/egress (any vocabulary)", "ssrf", 0.6, 0.7, "egress allowlist", handoff="appsec"),
    _sem("sc.sem.webhook", Category.INTEGRATION_EXTENSIBILITY, "Webhook replay (any vocabulary)", "webhook_replay", 0.5, 0.5, "replay protection"),
    _sem("sc.sem.oauth", Category.INTEGRATION_EXTENSIBILITY, "Over-broad OAuth scope (any vocabulary)", "oauth_scope", 0.5, 0.6, "scope minimization"),
    _sem("sc.sem.trial", Category.LICENSE_ENTITLEMENT, "Serial-trial weakness (any vocabulary)", "serial_trial", 0.5, 0.5, "identity dedupe + limits"),
]


def load_json_scenarios() -> list[AbuseScenario]:
    """Merge community/operator scenarios from heel/scenarios_lib/*.json — addable without code."""
    out = []
    d = os.path.join(os.path.dirname(__file__), "scenarios_lib")
    for fn in sorted(glob.glob(os.path.join(d, "*.json"))):
        try:
            with open(fn) as fh:
                for s in json.load(fh):
                    out.append(AbuseScenario(
                        id=s["id"], category=Category(s["category"]), objective=s["objective"],
                        target_affordance_pattern={"kind": s["kind"]},
                        probe_strategy=s.get("probe_strategy", s["id"]),
                        success_criterion=s["success_criterion"],
                        severity_model=s["severity_model"],
                        applies_when=AppliesWhen(s.get("applies_when", "always")),
                        source=ScenarioSource.SEED, recommended_control=s.get("recommended_control", ""),
                        exploitability_reduction=s.get("exploitability_reduction", 0.6),
                        handoff=s.get("handoff", ""), classification_impact=s.get("classification_impact")))
        except Exception:
            continue
    return out


def all_seed_scenarios(semantic: bool = True) -> list[AbuseScenario]:
    # semantic family ON by default: it generalizes to vocabularies the library didn't author
    return SEED_SCENARIOS + (SEMANTIC_SCENARIOS if semantic else []) + load_json_scenarios()


def list_scenarios(filter_category: str | None = None, include_discovered: list | None = None,
                   semantic: bool = True) -> list[AbuseScenario]:
    out = all_seed_scenarios(semantic=semantic) + list(include_discovered or [])
    if filter_category:
        out = [s for s in out if s.category.value == filter_category]
    return out


SEED_BY_ID = {s.id: s for s in SEED_SCENARIOS}
