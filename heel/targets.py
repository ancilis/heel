"""
HEEL — synthetic targets with planted abuse vectors (spec §5). The falsifiable spine.

Two built-in synthetic products with seeded ground truth, so HEEL is fully demonstrable
with NO real target. The adversarial agent probes a target's `Affordance` surface; the
coverage backtest scores discovered vectors against the planted ones.

  * SaaS target (non-AI): routes/auth, a usage meter, a trial flow, an export feature,
    multi-tenant records, a billing tier, a referral system — planted vectors from
    categories 1–9. It has NO agent surface, so category 10 must cleanly yield nothing.
  * AI/agent target: the above PLUS an agent feature with tools and an MCP-style surface —
    additional planted vectors from category 10.

Each affordance is HARDENED (control present) or VULNERABLE (a planted weakness → a
ground-truth PlantedVector), with a few DECOYS (look abusable, are hardened — false-
positive bait) and one DEGENERATE (present but unreachable — plausibility-weighting bait).
"""
from __future__ import annotations

from .contracts import (
    Affordance,
    Category,
    PlantedVector,
    Severity,
    SyntheticTarget,
)

PLAUSIBILITY_FLOOR = 0.25


def _aff(id, kind, category, planted, reach, sev=None, guard=None, decoy=False, **props):
    return Affordance(
        id=id, kind=kind, category=category, properties=props,
        guard_present=(guard if guard is not None else planted is None),
        reachability=reach, planted_weakness=planted,
        true_severity=sev, decoy=decoy,
    )


def _planted(target_id, affs):
    pv = []
    for a in affs:
        if a.planted_weakness and not a.decoy:
            pv.append(PlantedVector(
                id=f"pv:{target_id}:{a.id}", target_id=target_id, category=a.category,
                affordance_id=a.id, weakness=a.planted_weakness,
                true_severity=a.true_severity or Severity(0.5, 0.5),
                reachable=a.reachability >= PLAUSIBILITY_FLOOR,
            ))
    return pv


# --------------------------------------------------------------------------- #
# Non-AI SaaS target
# --------------------------------------------------------------------------- #
def build_saas_target() -> SyntheticTarget:
    A = [
        # --- planted (categories 1–9) ---
        _aff("export_records", "export", Category.DATA_HARVESTING, "export_no_entitlement_check",
             0.85, Severity(0.7, 0.8), route="/api/export", entitlement="pro", note="bulk export not entitlement-checked"),
        _aff("usage_meter", "meter", Category.LICENSE_ENTITLEMENT, "meter_reset_exploit",
             0.7, Severity(0.75, 0.7), route="/api/usage", reset_window="client_controlled"),
        _aff("record_get", "record", Category.COMPLIANCE_BOUNDARY, "cross_tenant_idor",
             0.8, Severity(0.8, 0.9), route="/api/records/{id}", tenant_check="missing"),
        _aff("premium_toggle", "flag", Category.UNINTENDED_ENDPOINTS, "client_flag_tier_bypass",
             0.75, Severity(0.6, 0.7), flag="isPremium", gated_by="client"),
        _aff("trial_signup", "trial", Category.LICENSE_ENTITLEMENT, "serial_trial",
             0.65, Severity(0.5, 0.5), route="/signup", identity_check="email_only"),
        _aff("admin_purge", "admin_action", Category.COMPLIANCE_BOUNDARY, "unlogged_admin_action",
             0.55, Severity(0.6, 0.7), route="/admin/purge", audit_logged=False),
        _aff("internal_debug", "endpoint", Category.UNINTENDED_ENDPOINTS, "hidden_endpoint",
             0.6, Severity(0.65, 0.75), route="/internal/debug", documented=False, client_reachable=True),
        _aff("referral_credit", "referral", Category.TRUST_ECONOMY, "referral_self_deal",
             0.6, Severity(0.55, 0.6), route="/referral/redeem", self_referral_check="missing"),
        _aff("account_recovery", "auth_reset", Category.IDENTITY_ACCOUNT, "weak_account_recovery",
             0.65, Severity(0.6, 0.7), route="/recover", recovery_check="weak"),
        # NOT a single-affordance vuln — only abusable when CHAINED with weak recovery (→ ato_chain)
        _aff("session_mgmt", "session", Category.IDENTITY_ACCOUNT, None, 0.6, guard=True,
             route="/session", session_rotation="none"),
        # --- planted but NOT covered by any seed scenario → the swarm must DISCOVER it ---
        _aff("webhook_endpoint", "integration", Category.INTEGRATION_EXTENSIBILITY, "webhook_replay",
             0.6, Severity(0.5, 0.5), route="/webhooks/in", replay_protection="missing"),
        # --- planted, reachable, but NOT a "missing-control" signal → a genuine MISS for the
        #     ADVERSARIAL class (honest FN) that the OPPORTUNISTIC-human class closes (coupon stacking) ---
        _aff("promo_stacking", "endpoint", Category.LICENSE_ENTITLEMENT, "coupon_stacking",
             0.6, Severity(0.5, 0.5), route="/checkout/apply", stackable=True, client_reachable=True),
        # --- commercial-gaming affordances (gamed WITHIN normal affordances by the §3.2 class) ---
        _aff("seats", "seat", Category.LICENSE_ENTITLEMENT, "seat_sharing",
             0.7, Severity(0.5, 0.5), route="/team/seats", sharing_detection="none"),
        _aff("region_pricing", "region", Category.LICENSE_ENTITLEMENT, "region_arbitrage",
             0.6, Severity(0.5, 0.6), route="/billing/region", region_check="ip_only"),
        # --- requires CHAINING two affordances → neither single-affordance class finds it
        #     (a genuine FN that survives both classes; affordance-chaining is Phase-3 swarm work) ---
        _aff("ato_chain", "chain", Category.IDENTITY_ACCOUNT, "multi_step_ato",
             0.55, Severity(0.7, 0.8), route="(reset → session-fixation)", chain_required=True),
        # --- decoys (hardened; FP bait) ---
        _aff("export_billing", "export", Category.DATA_HARVESTING, None, 0.8, guard=True, decoy=True,
             route="/api/billing/export", entitlement="checked", note="looks like export, properly gated"),
        _aff("admin_rotate_keys", "admin_action", Category.COMPLIANCE_BOUNDARY, None, 0.5, guard=True, decoy=True,
             route="/admin/rotate", audit_logged=True),
        # hardened decoys that SHARE property names with vulnerable affordances but SAFE values —
        # the precise probes must correctly NOT fire (true negatives → the low FP rate is earned).
        _aff("record_get_safe", "record", Category.COMPLIANCE_BOUNDARY, None, 0.7, guard=True, decoy=True,
             route="/api/records2/{id}", tenant_check="enforced"),
        _aff("usage_meter_safe", "meter", Category.LICENSE_ENTITLEMENT, None, 0.6, guard=True, decoy=True,
             route="/api/usage2", reset_window="server_authoritative"),
        _aff("premium_safe", "flag", Category.UNINTENDED_ENDPOINTS, None, 0.6, guard=True, decoy=True,
             flag="isPro", gated_by="server"),
        # --- degenerate (present but unreachable; plausibility-weighting bait) ---
        _aff("legacy_import", "endpoint", Category.UNINTENDED_ENDPOINTS, "deep_chain_only",
             0.12, Severity(0.3, 0.4), route="/legacy/import", client_reachable=False, requires="5-step chain"),
    ]
    return SyntheticTarget(
        id="synthetic-saas", kind="saas", has_agent_surface=False,
        affordances=A, planted_vectors=_planted("synthetic-saas", A),
        description="Multi-tenant SaaS: auth, usage meter, trial, export, records, billing tier, referrals. No AI.",
    )


# --------------------------------------------------------------------------- #
# AI / agent target (superset + category 10)
# --------------------------------------------------------------------------- #
def build_ai_target() -> SyntheticTarget:
    base = build_saas_target().affordances
    agent = [
        _aff("agent_tool_export", "agent_tool", Category.AGENT_MCP_SURFACE, "agent_tool_overscope",
             0.8, Severity(0.8, 0.9), tool="export_all", granted_scope="all_tenants", intended_scope="own_tenant"),
        _aff("agent_infer_loop", "agent_tool", Category.AGENT_MCP_SURFACE, "inference_cost_amplification",
             0.7, Severity(0.45, 0.55), tool="research", multi_step="unbounded", amplification="cheap->expensive"),
        _aff("agent_retrieval", "agent_tool", Category.AGENT_MCP_SURFACE, "agent_cross_tenant_retrieval",
             0.75, Severity(0.8, 0.9), tool="rag_search", tenant_filter="missing"),
        _aff("agent_priv_tool", "agent_tool", Category.AGENT_MCP_SURFACE, "confused_deputy_tool",
             0.65, Severity(0.6, 0.7), tool="admin_action", authz_check="caller_assumed"),
        # hardened agent-tool decoy: scope matches intent → the overscope probe must NOT fire
        _aff("agent_tool_safe", "agent_tool", Category.AGENT_MCP_SURFACE, None, 0.7, guard=True, decoy=True,
             tool="summarize", granted_scope="own_tenant", intended_scope="own_tenant"),
        _aff("mcp_connector_x", "mcp_connector", Category.AGENT_MCP_SURFACE, "mcp_context_bleed",
             0.6, Severity(0.7, 0.7), connector="external", context_isolation="missing"),
        # content guardrail — PRESENT (hardened). Verified with SAFE canaries only; no generation.
        _aff("content_guardrail", "content_guardrail", Category.CONTENT_POLICY, None, 0.7, guard=True,
             canary="benign", blocks_prohibited=True),
        # a true-vuln class (SSRF in url-fetch) — HEEL flags handoff_to_appsec, does not weaponize
        _aff("url_fetch", "agent_tool", Category.FUNCTION_ABUSE, "ssrf_url_fetch",
             0.6, Severity(0.6, 0.7), tool="fetch_url", allowlist="missing", handoff="appsec"),
        # a pure model-jailbreak SURFACE — NOT HEEL's lane; flagged handoff_to_model_redteam, never
        # weaponized and never counted as a product-abuse finding (lane discipline, §4.10 boundary).
        _aff("agent_prompt_surface", "agent_tool", Category.AGENT_MCP_SURFACE, None,
             0.5, guard=True, tool="chat", jailbreak_surface=True, handoff="model_redteam"),
    ]
    A = base + agent
    return SyntheticTarget(
        id="synthetic-ai", kind="ai_agent", has_agent_surface=True,
        affordances=A, planted_vectors=_planted("synthetic-ai", A),
        description="The SaaS target PLUS an agent feature with tools and an MCP-style surface.",
    )


TARGETS = {t.id: t for t in (build_saas_target(), build_ai_target())}


def get_target(target_id: str) -> SyntheticTarget | None:
    return TARGETS.get(target_id)
