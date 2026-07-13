# ARCEO Hosted — Threat Model

Scope: the hosted control + execution planes over the open-source engine. Status: design + the
implemented control-plane core; execution-plane controls are designed, not yet built (Phase 3).

## Assets
Authorization scopes & signing key; tenant data (runs, findings, containment log); subscription/
billing state; API keys; verified-target proofs; the worker egress boundary.

## Trust boundaries
Untrusted: agents, MCP/API callers, imported target content, webhook payloads, job fields. Trusted
only after server-side verification: authenticated human sessions, DB-stored roles, signature-verified
webhooks, proof-of-control-verified targets.

## Threats and controls
| # | Threat | Control | Status |
|---|---|---|---|
| T1 | Scope mint/widen via MCP/API/agent/injection | `scope.py`: HMAC-signed, human-only, no write path over any agent surface; hosted scope creation (Phase 3) is an isolated human-only path w/ step-up, confirmation, expiry, immutable audit | core inherited; hosted path pending |
| T2 | Cross-tenant access / IDOR | `workspace_id` on every record; `tenancy.require()` choke point; Postgres RLS (prod); adversarial cross-tenant tests | core done; RLS + fuzz pending |
| T3 | Confused deputy / target substitution | targets pinned to verified proof; workers re-verify target server-side; egress restricted to the run's single verified target | designed (Phase 3) |
| T4 | SSRF / DNS rebinding / private-address egress | egress guard resolves + pins IP, rejects private/link-local/loopback/metadata, blocks redirects & hostname→IP changes | designed (Phase 3) |
| T5 | Webhook spoofing / replay / reorder | `verify_webhook_signature` (HMAC + replay window); event dedupe; monotonic version + legal-transition guard | **done** |
| T6 | Billing races / quota evasion | append-only ledger, `BEGIN IMMEDIATE` reserve, idempotency keys, verified-run subset ceiling | **done** |
| T7 | Free-tier cost abuse / trial farming | atomic caps, per-run budgets, signup throttles, proof-of-uniqueness, global+tenant kill switches | ledger done; abuse defenses Phase 3/7 |
| T8 | Supply chain | zero runtime deps in core; SBOM + signed provenance (existing CI); image/secret scanning | partial (existing) |
| T9 | Secret exposure | signing key + vendor secrets in secret manager (prod); API keys hashed at rest; no secrets in repo (CI guard) | keys hashed done; KMS pending |
| T10 | Findings weaponization / real exfil | contained, canary-only findings; no working exploit payloads; model kept in-lane | core inherited |

## Residual risks
Execution-plane egress/isolation controls (T3, T4) are designed but unbuilt — no verified-target runs
should be enabled in production until Phase 3 lands and Sol ratifies. Billing atomicity note in
SELF_REVIEW #2. All controls await mandated Sol review.
