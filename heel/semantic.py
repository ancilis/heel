"""
HEEL — semantic signal matching (Phase 3, the honest generalization axis).

Exact property==value criteria don't generalize to independently-authored vocabularies. A scenario
can instead declare a SEMANTIC signal: a weakness family recognized by topic keywords in the
property KEY plus permissive indicators in the VALUE (and the absence of a hardened indicator).
Topic+permissive (not topic alone) keeps precision: 'tenant_check: enforced' won't match because
'enforced' is hardened.

The catalog is tuned on the DEV held-out set (heel/heldout/targets.json) + general security
knowledge, and measured on a FROZEN TEST set authored independently and never inspected by the
tuner (heel/heldout/test_targets.json) — so reported recall is not overfit. Each signal carries its
category/control so the SEMANTIC_SCENARIOS are generated from this catalog (heel/scenarios.py).
"""
from __future__ import annotations

import re

from .contracts import Category

C = Category

_TOK = re.compile(r"[^a-z0-9]+")


def _norm(s) -> str:
    # underscore-bounded token stream so matches anchor at token boundaries, not mid-word
    # (fixes substring collisions like 'orm' in 'format', 'ttl' in 'throttle', 'allowed' in 'disallowed')
    return "_" + "_".join(t for t in _TOK.split(str(s).lower()) if t) + "_"


def _anchored(needle: str, norm_haystack: str) -> bool:
    # needle must begin at a token boundary (allows suffixes: 'seat'->'seats', 'recover'->'recovery')
    return ("_" + needle.strip("_").replace("-", "_")) in norm_haystack

# NB: deliberately NO bare "true"/"yes"/"enabled" — boolean polarity is property-dependent
# (audit_logged:true is GOOD, acts_on_content:true is BAD), so a global "true" wrecks precision.
# Where true==weakness, the signal's permissive token is the EXPLICIT bad word (e.g. "passthrough").
# token-anchored permissive values: distinctive whole words + explicit "no_X" phrases only.
# NB no bare "true"/"enabled" (polarity is property-dependent), no "never"/"fixed" (negation-
# ambiguous), no ultra-short prefixes like "no"/"all" (would anchor 'normal'/'allocation'). Where
# true==weakness the signal matches the explicit bad word ("passthrough", "no_check", ...).
_PERMISSIVE = ("missing", "none", "off", "disabled", "shared", "global", "wildcard", "allowed",
               "unbounded", "unlimited", "unrestricted", "weak", "client", "browser", "frontend",
               "cross_tenant", "cross_account", "public", "settable", "absent", "sequential",
               "incrementing", "monotonic", "guessable", "arbitrary", "external", "infinite",
               "reused", "plaintext", "exposed", "unverified", "unauthenticated", "anyone",
               "spoofable", "disposable", "unpinned", "ignored", "unsandboxed", "passthrough",
               "unscoped", "false", "ip_only", "email_only", "soft_delete", "flag_only", "retained",
               "indefinite", "no_cooldown", "no_check", "no_limit", "no_rate", "no_verification",
               "no_throttle", "no_dedupe", "no_cap", "not_emitted", "not_enforced", "not_validated")
# values that mean the control IS present (suppress a match)
_HARDENED = ("enforced", "server", "strict", "scoped", "pinned", "required", "verified", "rotated",
             "isolated", "allowlist", "per_tenant", "per-tenant", "signed", "rate_limited", "limited",
             "capped", "gated", "blocked", "sandboxed", "hashed", "encrypted", "expiring", "audited",
             "reviewed", "approved", "validated", "restricted", "denied", "hard_delete", "purged",
             "unique", "verified_purchase", "step_up", "mfa_required", "short_lived")

# signal -> (topic keywords in the property KEY, category, control, handoff, likelihood, impact)
SEMANTIC_SIGNALS = {
    # data / tenancy
    "tenant_isolation": (("tenant", "cross_account", "cross-account", "cross_tenant", "row_secur",
                          "row_level", "multitenan", "account_scope", "account_isolation", "org_scope"),
                         C.COMPLIANCE_BOUNDARY, "enforce per-tenant row-level scoping", "", 0.8, 0.9),
    "bulk_export": (("export", "download", "bulk", "extract", "dump", "scrape", "csv", "siphon"),
                    C.DATA_HARVESTING, "entitlement-gate + rate-limit bulk reads/exports", "", 0.6, 0.7),
    "enumeration": (("sequential_id", "id_format", "id_scheme", "enumerab", "guessable", "incrementing",
                     "object_id", "record_id"), C.DATA_HARVESTING, "non-enumerable ids + per-tenant limits", "", 0.5, 0.6),
    # license / entitlement
    "meter_reset": (("meter", "usage", "quota", "counter", "reset", "billing_window", "reconcil"),
                    C.LICENSE_ENTITLEMENT, "server-authoritative metering windows", "", 0.6, 0.6),
    "tier_gate": (("tier", "premium", "plan", "entitle", "feature_flag", "paywall", "gate", "upgrade",
                   "enforced_where"), C.UNINTENDED_ENDPOINTS, "gate tier on server-verified entitlement", "", 0.6, 0.7),
    "seat_sharing": (("seat", "concurrent_session", "concurrent_login", "device_limit", "shared_login",
                      "login_check", "session_cap"), C.LICENSE_ENTITLEMENT, "concurrent-session/device limits per seat", "", 0.5, 0.5),
    "serial_trial": (("trial", "signup_dedupe", "dedupe", "fingerprint", "uniqueness_key", "trials_per"),
                     C.LICENSE_ENTITLEMENT, "device/identity fingerprint + trial-per-identity", "", 0.5, 0.5),
    "region_arbitrage": (("region_pricing", "geo_pricing", "region_check", "billing_region", "geo_check"),
                         C.LICENSE_ENTITLEMENT, "verify billing region via payment instrument", "", 0.5, 0.6),
    # unintended endpoints
    "mass_assignment": (("mass_assign", "writable_field", "whitelist", "passthrough", "orm", "role_field",
                         "privilege_field", "billing_owner", "writable_by_self"), C.UNINTENDED_ENDPOINTS,
                        "allowlist writable fields server-side", "", 0.6, 0.8),
    "hidden_route": (("debug", "undocumented", "hidden_route", "internal_route", "backdoor", "admin_route",
                      "documented"), C.UNINTENDED_ENDPOINTS, "remove/auth-gate undocumented endpoints", "", 0.5, 0.7),
    "authz_missing": (("auth_required", "auth_guard", "authorization", "access_control", "authz",
                       "header_settable", "auth_check"), C.UNINTENDED_ENDPOINTS, "server-side authorization on every route", "", 0.6, 0.8),
    # function abuse
    "ssrf": (("fetch", "url_", "egress", "outbound", "proxy", "ssrf", "delivery_target", "private_ip",
              "metadata_ip", "rebind"), C.FUNCTION_ABUSE, "egress allowlist + metadata-endpoint block", "appsec", 0.6, 0.8),
    "cost_amplification": (("inference", "compute_loop", "fanout", "recursion", "job_depth", "token_budget",
                            "llm_calls", "max_steps", "concurrency_cap"), C.FUNCTION_ABUSE,
                           "per-call cost ceilings + bounded multi-step", "", 0.6, 0.6),
    "notification_spam": (("recipient", "email_snapshot", "notification", "sms", "send_to", "max_recipients"),
                          C.FUNCTION_ABUSE, "rate-limit + restrict recipients to members", "", 0.5, 0.5),
    # identity / account
    "recovery_weak": (("recover", "password_reset", "otp", "mfa", "2fa", "reset_check", "verification_strength"),
                      C.IDENTITY_ACCOUNT, "strengthen + rate-limit account recovery", "", 0.6, 0.7),
    "sybil_signup": (("signup", "registration", "account_creation", "captcha", "proof_of_unique"),
                     C.IDENTITY_ACCOUNT, "proof-of-uniqueness + velocity limits on signup", "", 0.5, 0.5),
    "session_security": (("session_rotation", "session_fixation", "token_lifetime", "jwt", "session_expiry",
                          "token_reuse"), C.IDENTITY_ACCOUNT, "rotate sessions; bind + expire tokens", "", 0.6, 0.7),
    # trust / economy
    "review_manipulation": (("review", "rating", "vote", "reputation", "feedback_provenance"),
                            C.TRUST_ECONOMY, "verified-purchase weighting + provenance", "", 0.4, 0.5),
    "payout_fraud": (("payout", "refund", "balance", "wallet", "points", "credits", "cashout", "loyalty"),
                     C.TRUST_ECONOMY, "velocity + balance verification on value movement", "", 0.5, 0.6),
    "referral_selfdeal": (("referral", "self_referral", "invite_credit"), C.TRUST_ECONOMY,
                          "block self-referral + velocity limits", "", 0.4, 0.5),
    # integration / extensibility
    "webhook_replay": (("webhook", "callback", "replay", "nonce", "signature_check"),
                       C.INTEGRATION_EXTENSIBILITY, "webhook nonce + timestamp; reject replays", "", 0.5, 0.5),
    "oauth_scope": (("oauth", "token_scope", "app_scope", "granted_scopes"), C.INTEGRATION_EXTENSIBILITY,
                    "OAuth scope minimization + per-app review", "", 0.5, 0.6),
    "api_key_leak": (("api_key", "secret", "credential", "access_token", "token_storage", "key_in"),
                     C.INTEGRATION_EXTENSIBILITY, "rotate + vault secrets; never log/return keys", "", 0.6, 0.7),
    # compliance
    "audit_gap": (("audit", "logging", "trail", "logged", "recorded", "audit_event"),
                  C.COMPLIANCE_BOUNDARY, "complete audit-log coverage for the action", "", 0.6, 0.7),
    "residency": (("residency", "data_region", "processing_region", "jurisdiction", "data_location"),
                  C.COMPLIANCE_BOUNDARY, "pin storage/processing region per tenant", "", 0.5, 0.7),
    "retention": (("retention", "deletion", "erase", "purge", "hard_delete", "delete_semantics", "ttl"),
                  C.COMPLIANCE_BOUNDARY, "enforce hard-delete + retention limits", "", 0.5, 0.6),
    "consent": (("consent", "opt_in", "lawful_basis", "data_class"), C.COMPLIANCE_BOUNDARY,
                "consent/authorization gate before processing", "", 0.5, 0.6),
    # agent / MCP surface (gated to has_agent_surface in scenarios.py)
    "agent_scope": (("tool_scope", "tool_access", "granted_scope", "capabilit", "agent_scope", "tool_permission",
                     "intended_scope"), C.AGENT_MCP_SURFACE, "scope agent tool permissions to caller intent/tenant", "", 0.8, 0.9),
    "retrieval_tenant": (("retriev", "rag", "corpus", "vector", "memory_scope", "context_scope", "knowledge_base"),
                         C.AGENT_MCP_SURFACE, "enforce tenant filter in retrieval/RAG/memory", "", 0.8, 0.9),
    "confused_deputy": (("authz_at_tool", "tool_authz", "caller_assumed", "privileged_tool", "deputy"),
                        C.AGENT_MCP_SURFACE, "re-check authorization at the privileged tool", "", 0.6, 0.7),
    "mcp_bleed": (("context_isolation", "connector_isolation", "cross_server", "mcp_context", "transitive_trust"),
                  C.AGENT_MCP_SURFACE, "isolate per-connector context; no cross-server bleed", "", 0.6, 0.6),
    "tool_poisoning": (("tool_metadata", "connector_trust", "third_party_tool", "plugin_review", "tool_pinning"),
                       C.AGENT_MCP_SURFACE, "sandbox + review third-party tool metadata; pin versions", "", 0.6, 0.7),
    "indirect_injection": (("acts_on_content", "processes_untrusted", "content_triggered", "autonomous_action",
                            "untrusted_content"), C.AGENT_MCP_SURFACE, "treat processed content as untrusted; gate actions", "", 0.7, 0.8),
}


def _value_permissive(v) -> bool:
    if v is False or v in (0, None):
        return True
    vn = _norm(v)
    if any(_anchored(h, vn) for h in _HARDENED):  # a present control suppresses the match (precision-favoring)
        return False
    return any(_anchored(p, vn) for p in _PERMISSIVE)


def semantic_match(signal: str, aff) -> bool:
    spec = SEMANTIC_SIGNALS.get(signal)
    if not spec:
        return False
    topics = spec[0]
    for k, v in aff.properties.items():
        kn = _norm(k)
        if any(_anchored(t, kn) for t in topics) and _value_permissive(v):
            return True
    return False
