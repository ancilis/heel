# ARCEO — Pricing & Entitlements

The **code** in `arceo/saas/catalog.py` is the source of truth. This document explains the shape
and the unit economics. Prices are USD, monthly unless noted; annual = 10× monthly (2 months free).

## Metered value (what we charge for — durable, costly)
- **rehearsal runs** (credits) — the core costly unit (agent/LLM + compute time)
- **verified targets** — proof-of-control-gated real targets
- **execution concurrency** — parallel workers
- **retained results** — retention window (days)
- **seats** — org members
- **integrations / private-runner capacity** — CI/API/MCP + dedicated runners (paid tiers)

We do **not** gate UI decoration.

## Catalog
| Plan | Price/mo | Runs/mo | Verified targets | Concurrency | Retention | Seats | Surfaces | Support |
|---|---|---|---|---|---|---|---|---|
| **Free** | $0 (no card) | 20 synthetic + 5 verified | 1 | 1 | 7 d | 1 | CLI, guided UI | community |
| **Pro** | $49 | 300 | 5 | 3 | 30 d | 3 | + API, MCP, exports, scheduled regressions | email |
| **Team** | $199 | 1,500 | 25 | 8 | 90 d | 10 | + RBAC, audit export, integrations | priority |
| **Enterprise** | custom (annual) | custom | custom | custom / dedicated | custom | custom | + SSO/SAML-OIDC, SCIM*, data-region*, private runners | SLA conversation |

\* SSO/SCIM/data-region are **contact-sales / deployment-option** capabilities. Where not configured
they are disabled and honestly surfaced through the enterprise flow — never dead checkboxes.

## Free-tier hard maximum liability
Every free unit is atomically capped. Worst-case monthly cost per free workspace:
- 20 synthetic runs (deterministic StubModel, no LLM spend) ≈ **$0 marginal**.
- 5 verified-target runs × per-run budget ceiling (CPU wall-clock ≤ 60 s, network egress restricted
  to the single verified target, token budget capped) ≈ small bounded compute.
- Concurrency 1, retention 7 d, 1 seat, 1 verified target.
- Trial-farming defenses: proof-of-uniqueness on signup, target proof-of-control (DNS TXT / HTTP),
  per-IP and per-identity signup throttles, global + tenant kill switches.

Result: free-tier liability is a **calculable, bounded** number per workspace and globally capped by
a platform circuit breaker. See `docs/saas/PRODUCT.md` §cost-model.

## Overage behavior
Free/Pro: hard stop at quota with an in-context upgrade path (no surprise bills). Team: soft cap with
admin-approved metered overage (opt-in). Enterprise: contractual.

## Grandfathering & versioning
Catalog entries are versioned (`catalog_version`). A subscription pins the version it was created on;
migrations are explicit. Entitlements are computed from the pinned catalog version + live subscription
state, never from client claims or raw Stripe metadata.
