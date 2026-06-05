"""
HEEL — semantic signal matching (Phase 3, the honest generalization axis).

Exact property==value criteria don't generalize to independently-authored vocabularies (the
held-out eval shows this). A scenario can instead declare a SEMANTIC signal: a weakness family
recognized by topic keywords in the property KEY plus permissive indicators in the VALUE (and the
absence of a hardened indicator). This generalizes one scenario to a synonym family — pure-stdlib,
no model. It is authored as a reasonable generalization; the held-out targets (authored by an
independent LLM swarm, blind to this catalog) are the fair test of whether it anticipates real
vocabularies. Topic+permissive (not topic alone) keeps precision: 'tenant_check: enforced' will not
match because 'enforced' is a hardened value.
"""
from __future__ import annotations

from .contracts import Category

# permissive (weakness-indicating) and hardened (safe) value vocabularies
_PERMISSIVE = ("missing", "none", "off", "disabled", "shared", "global", "all", "any", "allowed",
               "open", "unbounded", "unlimited", "unrestricted", "weak", "client", "browser",
               "frontend", "local", "no_", "cross", "wildcard", "public", "settable", "user", "*")
_HARDENED = ("enforced", "server", "strict", "scoped", "pinned", "required", "verified", "rotated",
             "isolated", "allowlist", "per_tenant", "per-tenant", "signed", "rate_limited")

# signal -> (topic keywords matched in the property KEY, category, recommended control, handoff)
SEMANTIC_SIGNALS = {
    "tenant_isolation": (("tenant", "cross_account", "cross-account", "cross_tenant", "row_secur",
                          "row_level", "multitenan", "account_scope", "account_isolation"),
                         Category.COMPLIANCE_BOUNDARY, "enforce per-tenant row-level scoping", ""),
    "bulk_export": (("export", "download", "bulk", "extract", "dump", "scrape"),
                    Category.DATA_HARVESTING, "entitlement-gate + rate-limit bulk reads/exports", ""),
    "meter_reset": (("meter", "usage", "quota", "counter", "reset", "window", "throttle"),
                    Category.LICENSE_ENTITLEMENT, "server-authoritative metering windows", ""),
    "tier_gate": (("tier", "premium", "plan", "entitle", "feature_flag", "paywall", "gate", "upgrade"),
                  Category.UNINTENDED_ENDPOINTS, "gate tier on server-verified entitlement", ""),
    "audit_gap": (("audit", "logging", "trail", "logged", "recorded"),
                  Category.COMPLIANCE_BOUNDARY, "complete audit-log coverage for the action", ""),
    "recovery_weak": (("recover", "reset", "password", "otp", "mfa", "2fa", "verification"),
                      Category.IDENTITY_ACCOUNT, "strengthen + rate-limit account recovery", ""),
    "agent_scope": (("tool_scope", "tool_access", "grant", "capabilit", "agent_scope", "permission"),
                    Category.AGENT_MCP_SURFACE, "scope agent tool permissions to caller intent/tenant", ""),
    "retrieval_tenant": (("retriev", "rag", "corpus", "vector", "index", "memory", "context_scope"),
                         Category.AGENT_MCP_SURFACE, "enforce tenant filter in retrieval/RAG", ""),
    "ssrf": (("fetch", "url_", "egress", "outbound", "proxy", "ssrf"),
             Category.FUNCTION_ABUSE, "egress allowlist + metadata-endpoint block", "appsec"),
    "webhook_replay": (("webhook", "callback", "replay", "nonce", "signature_check"),
                       Category.INTEGRATION_EXTENSIBILITY, "webhook nonce + timestamp; reject replays", ""),
    "oauth_scope": (("oauth", "token_scope", "app_scope"),
                    Category.INTEGRATION_EXTENSIBILITY, "OAuth scope minimization", ""),
    "serial_trial": (("trial", "signup", "dedupe", "fingerprint"),
                     Category.LICENSE_ENTITLEMENT, "device/identity fingerprint + trial-per-identity", ""),
}


def _value_permissive(v) -> bool:
    if v is False or v in (0, None):
        return True
    sv = str(v).lower()
    if any(h in sv for h in _HARDENED):
        return False
    return any(perm in sv for perm in _PERMISSIVE)


def semantic_match(signal: str, aff) -> bool:
    spec = SEMANTIC_SIGNALS.get(signal)
    if not spec:
        return False
    topics = spec[0]
    for k, v in aff.properties.items():
        kl = str(k).lower()
        if any(t in kl for t in topics) and _value_permissive(v):
            return True
    return False
