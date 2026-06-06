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
               "no_throttle", "no_dedupe", "no_cap", "not_emitted", "not_enforced", "not_validated",
               # research B3 additions (sourced; token-anchored, polarity-safe distinct words/phrases)
               "ungated", "no_limit_set", "full_access", "auto_approve", "optional", "disposable_allowed",
               "verbose", "permissive", "best_effort", "advisory_only", "default_open", "ui_only",
               "client_controlled", "anonymous", "unenforced", "account_specific", "not_scoped",
               "no_signature", "no_tenant_filter", "no_pinning")
# values that mean the control IS present (suppress a match)
_HARDENED = ("enforced", "server", "strict", "scoped", "pinned", "required", "verified", "rotated",
             "isolated", "allowlist", "per_tenant", "per-tenant", "signed", "rate_limited", "limited",
             "capped", "gated", "blocked", "sandboxed", "hashed", "encrypted", "expiring", "audited",
             "reviewed", "approved", "validated", "restricted", "denied", "hard_delete", "purged",
             "unique", "verified_purchase", "step_up", "mfa_required", "short_lived",
             # research B3 hardened additions (sourced)
             "least_privilege", "deny_by_default", "single_use", "constant_time", "idempotent",
             "audience_restricted", "tenant_scoped", "namespaced", "high_entropy", "non_sequential",
             "redacted", "fail_closed", "mandatory", "server_side", "constrained", "verified_only",
             "minimized", "vetted")

# signal -> (topic keywords in the property KEY, category, control, handoff, likelihood, impact)
# Enriched with the external research vocabulary harvest (Stripe/Kong/OWASP/MCP/Auth0/Microsoft etc.);
# only topics that realistically co-occur with a PERMISSIVE value are added (boolean-true-is-bad fields
# like destructiveHint/openWorldHint stay as EXACT research scenarios in scenarios_lib/research_owasp.json).
SEMANTIC_SIGNALS = {
    # data / tenancy
    "tenant_isolation": (("tenant", "cross_account", "cross-account", "cross_tenant", "row_secur",
                          "row_level", "multitenan", "account_scope", "account_isolation", "org_scope",
                          "organization_id", "workspace_id", "fgac", "partition", "tenant_id", "tenant_filter"),
                         C.COMPLIANCE_BOUNDARY, "enforce per-tenant row-level scoping", "", 0.8, 0.9),
    "bulk_export": (("export", "download", "bulk", "extract", "dump", "scrape", "csv", "siphon",
                     "export_scope", "export_row_limit", "download_cap", "report_export", "data_dump"),
                    C.DATA_HARVESTING, "entitlement-gate + rate-limit bulk reads/exports", "", 0.6, 0.7),
    "enumeration": (("sequential_id", "id_format", "id_scheme", "enumerab", "guessable", "incrementing",
                     "object_id", "record_id", "object_authorization", "pagination_max"),
                    C.DATA_HARVESTING, "non-enumerable ids + per-tenant limits", "", 0.5, 0.6),
    # license / entitlement   (Stripe Billing Meter object vocabulary)
    "meter_reset": (("meter", "usage", "quota", "counter", "reset", "billing_window", "reconcil",
                     "default_aggregation", "aggregation", "event_time_window", "value_settings",
                     "customer_mapping", "usage_type", "aggregate_usage", "meter_event", "grouping_window"),
                    C.LICENSE_ENTITLEMENT, "server-authoritative metering windows + idempotency", "", 0.6, 0.6),
    "tier_gate": (("tier", "premium", "plan", "entitle", "feature_flag", "paywall", "gate", "upgrade",
                   "enforced_where", "entitlement_check", "feature_gate", "plan_enforcement"),
                  C.UNINTENDED_ENDPOINTS, "gate tier on server-verified entitlement", "", 0.6, 0.7),
    "seat_sharing": (("seat", "concurrent_session", "concurrent_login", "device_limit", "shared_login",
                      "login_check", "session_cap", "max_concurrent", "floating_license", "named_user",
                      "idle_timeout", "overage", "seat_enforcement"),
                     C.LICENSE_ENTITLEMENT, "concurrent-session/device limits per seat", "", 0.5, 0.5),
    "serial_trial": (("trial", "signup_dedupe", "dedupe", "fingerprint", "uniqueness_key", "trials_per",
                      "trial_eligibility"), C.LICENSE_ENTITLEMENT, "device/identity fingerprint + trial-per-identity", "", 0.5, 0.5),
    "region_arbitrage": (("region_pricing", "geo_pricing", "region_check", "billing_region", "geo_check",
                          "billing_country", "region_validation"),
                         C.LICENSE_ENTITLEMENT, "verify billing region via payment instrument", "", 0.5, 0.6),
    # unintended endpoints
    "mass_assignment": (("mass_assign", "writable_field", "whitelist", "passthrough", "orm", "role_field",
                         "privilege_field", "billing_owner", "writable_by_self", "binding_mode",
                         "field_allowlist", "autobind", "overpost"), C.UNINTENDED_ENDPOINTS,
                        "explicit DTO/allowlist binding; never auto-bind privilege/money/verification fields", "", 0.6, 0.8),
    "hidden_route": (("debug", "undocumented", "hidden_route", "internal_route", "backdoor", "admin_route",
                      "documented", "debug_mode", "stack_traces", "docs_endpoint"),
                     C.UNINTENDED_ENDPOINTS, "remove/auth-gate undocumented + debug endpoints", "", 0.5, 0.7),
    "authz_missing": (("auth_required", "auth_guard", "authorization", "access_control", "authz",
                       "header_settable", "auth_check", "function_authorization"),
                      C.UNINTENDED_ENDPOINTS, "server-side authorization on every route", "", 0.6, 0.8),
    "zombie_api": (("deprecated", "legacy_route", "api_version", "inventory_managed", "zombie", "deprecated_route"),
                   C.UNINTENDED_ENDPOINTS, "maintain API inventory; retire deprecated versions; gateway authz", "", 0.35, 0.5),
    # function abuse
    "ssrf": (("fetch", "url_", "egress", "outbound", "proxy", "ssrf", "delivery_target", "private_ip",
              "metadata_ip", "rebind", "url_allowlist"), C.FUNCTION_ABUSE, "egress allowlist + metadata-endpoint block", "appsec", 0.6, 0.8),
    "cost_amplification": (("inference", "compute_loop", "fanout", "recursion", "job_depth", "token_budget",
                            "llm_calls", "max_steps", "concurrency_cap", "cost", "spend", "budget", "amplif",
                            "cost_cap", "per_user_rate_limit", "rate_limit", "throttle", "quota",
                            "window_size", "limit_by"), C.FUNCTION_ABUSE,
                           "per-principal cost/spend caps + rate limits on pay-per-use", "", 0.6, 0.6),
    "notification_spam": (("recipient", "email_snapshot", "notification", "sms", "send_to", "max_recipients",
                           "invite_rate_limit", "recipient_cap", "send_throttle", "invite"),
                          C.FUNCTION_ABUSE, "rate-limit + restrict recipients to members", "", 0.5, 0.5),
    "human_gated_automation": (("bot_protection", "step_pacing", "human_gate", "velocity", "anti_automation"),
                               C.FUNCTION_ABUSE, "anti-automation + per-account velocity on sensitive flows", "", 0.4, 0.4),
    # content policy
    "formula_injection": (("formula", "csv_escape", "export_sanit", "spreadsheet", "csv_injection",
                           "csv_escape_formulas"), C.CONTENT_POLICY,
                          "escape =,+,-,@/Tab/CR leading cells; prefix tab; sanitize exports", "", 0.4, 0.4),
    # identity / account
    "recovery_weak": (("recover", "password_reset", "otp", "mfa", "2fa", "reset_check", "verification_strength",
                       "reset_token", "reset_rate_limit", "otp_attempt_limit", "forgot_password",
                       "reset_token_expiry", "reset_token_entropy"),
                      C.IDENTITY_ACCOUNT, "strengthen + rate-limit account recovery; single-use short-lived tokens", "", 0.6, 0.7),
    "reset_enumeration": (("user_enumeration", "reset_response", "enumeration_protection", "generic_message"),
                          C.IDENTITY_ACCOUNT, "consistent generic, constant-time reset/login responses", "", 0.55, 0.3),
    "sybil_signup": (("signup", "registration", "account_creation", "captcha", "proof_of_unique",
                      "signup_verification", "account_creation_rate_limit", "disposable", "multi_account"),
                     C.IDENTITY_ACCOUNT, "proof-of-uniqueness + velocity limits on signup", "", 0.5, 0.5),
    "session_security": (("session_rotation", "session_fixation", "token_lifetime", "jwt", "session_expiry",
                          "token_reuse"), C.IDENTITY_ACCOUNT, "rotate sessions; bind + expire tokens", "", 0.6, 0.7),
    # trust / economy
    "review_manipulation": (("review", "rating", "vote", "reputation", "feedback_provenance",
                             "review_requires_purchase", "rating_dedup", "verified_purchase"),
                            C.TRUST_ECONOMY, "gate reviews on verified transactions; detect rating rings", "", 0.4, 0.5),
    "payout_fraud": (("payout", "refund", "balance", "wallet", "points", "credits", "cashout", "loyalty",
                      "chargeback", "dispute", "rebate", "settlement", "buyer_protection",
                      "refund_auto_approve", "refund_velocity"),
                     C.TRUST_ECONOMY, "evidence-based refunds; velocity tracking; hold accrual to settlement", "", 0.5, 0.6),
    "referral_selfdeal": (("referral", "self_referral", "invite_credit", "referrer", "referee",
                           "referral_reward"), C.TRUST_ECONOMY, "reward qualified actions; cross-match device/IP/payment", "", 0.4, 0.5),
    # integration / extensibility   (Stripe webhook + OAuth vocabulary)
    "webhook_replay": (("webhook", "callback", "replay", "nonce", "signature_check", "hmac",
                        "timestamp_validation", "replay_protection", "idempotency", "delivery_id",
                        "signing_secret", "event_id", "webhook_signature"),
                       C.INTEGRATION_EXTENSIBILITY, "verify HMAC + reject stale timestamps; dedupe + idempotent", "", 0.5, 0.5),
    "oauth_scope": (("oauth", "token_scope", "app_scope", "granted_scopes", "mandatory_scope", "audience",
                     "resource_indicator", "enable_implicit_grant", "enable_password_grant", "scope_enforcement"),
                    C.INTEGRATION_EXTENSIBILITY, "least-privilege scopes + audience restriction (RFC 8707)", "", 0.5, 0.6),
    "api_key_leak": (("api_key", "secret", "credential", "access_token", "token_storage", "key_in",
                      "key_scope", "key_rotation", "client_embedded"),
                     C.INTEGRATION_EXTENSIBILITY, "scoped restricted keys; vault not client; rotate + revoke", "", 0.6, 0.7),
    # compliance
    "audit_gap": (("audit", "logging", "trail", "logged", "recorded", "audit_event", "admin_action_logging",
                   "audit_trail"), C.COMPLIANCE_BOUNDARY, "complete audit-log coverage for the action", "", 0.6, 0.7),
    "residency": (("residency", "data_region", "processing_region", "jurisdiction", "data_location",
                   "region_pin", "locality", "residency_enforcement"),
                  C.COMPLIANCE_BOUNDARY, "pin storage/processing region per tenant", "", 0.5, 0.7),
    "retention": (("retention", "deletion", "erase", "purge", "hard_delete", "delete_semantics", "ttl",
                   "retention_period", "backup_retention", "erasure", "anonymization", "storage_limitation",
                   "deletion_enforcement"), C.COMPLIANCE_BOUNDARY, "enforce hard-delete + retention limits incl. backups", "", 0.5, 0.6),
    "consent": (("consent", "opt_in", "lawful_basis", "data_class", "consent_required", "consent_withdrawal"),
                C.COMPLIANCE_BOUNDARY, "consent/authorization gate before processing; honor withdrawal", "", 0.5, 0.6),
    "external_sharing": (("external_sharing", "anyone_link", "guest_access", "anonymous_access", "guest_invite",
                          "default_link", "sharing_level", "link_type", "link_expiration"),
                         C.COMPLIANCE_BOUNDARY, "restrict external/anonymous sharing; default to least-permissive links", "", 0.4, 0.6),
    "kyc_limits": (("kyc_level", "verification_tier", "transaction_limit", "daily_limit", "velocity_limit",
                    "source_of_funds"), C.COMPLIANCE_BOUNDARY, "tier transaction limits by KYC level; enforce velocity", "", 0.4, 0.55),
    # agent / MCP surface (gated to has_agent_surface in scenarios.py)
    "agent_scope": (("tool_scope", "tool_access", "granted_scope", "capabilit", "agent_scope", "tool_permission",
                     "intended_scope", "readonlyhint", "needs_approval", "needsapproval", "is_enabled"),
                    C.AGENT_MCP_SURFACE, "least-privilege tools; verify behavior not the hint", "", 0.8, 0.9),
    "retrieval_tenant": (("retriev", "rag", "corpus", "vector", "memory_scope", "context_scope", "knowledge_base",
                          "namespace", "embedding_isolation", "namespace_isolation"),
                         C.AGENT_MCP_SURFACE, "mandatory tenant filter-first retrieval; per-tenant namespaces", "", 0.8, 0.9),
    "confused_deputy": (("authz_at_tool", "tool_authz", "caller_assumed", "privileged_tool", "deputy",
                         "shared_credential", "per_user_identity", "credential_model", "delegation"),
                        C.AGENT_MCP_SURFACE, "propagate user identity; per-request token validation (RFC 8707)", "", 0.6, 0.7),
    "mcp_bleed": (("context_isolation", "connector_isolation", "cross_server", "mcp_context", "transitive_trust",
                   "server_isolation", "cross_server_context"),
                  C.AGENT_MCP_SURFACE, "isolate per-connector context; no cross-server bleed", "", 0.6, 0.6),
    "tool_poisoning": (("tool_metadata", "connector_trust", "third_party_tool", "plugin_review", "tool_pinning",
                        "tool_description_vetted", "tool_definition_pinned"),
                       C.AGENT_MCP_SURFACE, "vet + pin tool descriptions/schemas; sandbox third-party servers", "", 0.6, 0.7),
    "indirect_injection": (("acts_on_content", "processes_untrusted", "content_triggered", "autonomous_action",
                            "untrusted_content", "action_confirmation"),
                           C.AGENT_MCP_SURFACE, "treat processed content as untrusted; gate actions", "", 0.7, 0.8),
    "unbounded_agency": (("max_turns", "max_iterations", "iteration_limit", "tool_call_cap"),
                         C.AGENT_MCP_SURFACE, "cap turns/iterations + wall-clock timeout + per-session spend", "", 0.4, 0.45),
}


def _value_permissive(v) -> bool:
    if v is False or v in (0, None):
        return True
    vn = _norm(v)
    if any(_anchored(h, vn) for h in _HARDENED):  # a present control suppresses the match (precision-favoring)
        return False
    return any(_anchored(p, vn) for p in _PERMISSIVE)


def semantic_match(signal: str, aff) -> bool:
    return semantic_specificity(signal, aff) > 0


def semantic_specificity(signal: str, aff) -> int:
    """Length of the longest topic token that matches (0 = no match). A more SPECIFIC topic match
    (e.g. 'password_reset') is more likely the correct category than a generic one ('reset'), so
    this breaks dedup ties toward correct attribution — WITHOUT peeking at ground-truth category."""
    spec = SEMANTIC_SIGNALS.get(signal)
    if not spec:
        return 0
    best = 0
    for k, v in aff.properties.items():
        kn = _norm(k)
        if not _value_permissive(v):
            continue
        for t in spec[0]:
            if _anchored(t, kn):
                best = max(best, len(t.strip("_")))
    return best
