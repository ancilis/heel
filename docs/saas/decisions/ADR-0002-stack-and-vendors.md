# ADR-0002 — Hosted stack and vendor selection

Status: Accepted (amended 2026-07-13, see "As built") · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

## Context
Solo founder, low ops burden, secure defaults, few vendors, strong local dev, hard free-tier cost
ceilings. Existing strengths: pure-stdlib Python engine + a Next.js control room. Full production
deploy needs owner credentials (blockers), so choices must have excellent *local* fidelity.

## Decisions (with rejected alternatives)
| Concern | Choice | Rejected | Why |
|---|---|---|---|
| Control-plane API | **Python (stdlib http.server-based, framework-light)** extending the existing engine | FastAPI, Django | Preserves zero-dep core philosophy for local dev; hosted layer may add a thin ASGI server behind a gate. Keeps one language for engine+control. |
| Relational store | **Postgres** (managed: Neon/Supabase/RDS — owner picks account) with **SQLite for local/CI** via a thin store abstraction | MySQL, Mongo | Row-level security, strong tenancy, standard. SQLite keeps local dev/CI zero-infra; schema is portable. |
| Auth | **Vendor-native (Clerk or WorkOS/AuthKit)** for hosted; local dev uses a self-contained session/API-key module | Roll-your-own password auth | "Vendor-native auth over bespoke security" (spec §5). SSO/SCIM path via WorkOS for enterprise. |
| Billing | **Stripe** (see ADR-0003) | Paddle, Lemon Squeezy | Default candidate; test-clock + sandbox fidelity; customer portal. |
| Queue/workers | **SQLite-backed durable queue** locally (`JobPlane`: lease/reap/settle); managed queue or Postgres SKIP LOCKED in prod behind an interface | Redis/Celery, Temporal | Fewer vendors; the local queue is zero-infra and fully testable; prod swap is an adapter. |
| Secrets | Env + validated loader locally; **cloud secret manager** in prod | Committed config | Never commit secrets; rotation runbook. |
| Frontend | **Server-rendered hosted app** (`heel/saas/dashboard.py`) for v1; a dedicated hosted Next.js app is future commercial code | Relabel existing `web/` | `web/` is the engine's Apache-2.0 snapshot control room (ADR-0001); the hosted UI must be new commercial code, not a relicense of open code. |
| Hosting | Owner-selected (a container host for app + workers). Documented, not provisioned. | — | Requires owner accounts. |

## Local-first principle
Everything runs locally with **zero external accounts** (SQLite, in-process queue, stub billing,
stub auth) so the whole funnel is testable and demoable offline. Prod adapters swap in behind
interfaces once owner supplies credentials. This makes the build turnkey without pretending
external accounts exist.

## As built (2026-07-13)
What exists and is tested: SQLite stores and queue, self-contained session/API-key auth,
`StubBilling`, the stdlib HTTP control plane, and the server-rendered hosted app. Vendor auth
(Clerk/WorkOS), Postgres, the managed queue, and live Stripe are **selected but not implemented**;
each is an owner-credential-gated adapter swap (OWNER_ACTIONS). Nothing in this ADR should be read
as a claim that a production vendor integration exists today.

## Reversibility
Store/queue/auth/billing are behind interfaces (`store.py` pattern already exists). Swapping a
vendor is an adapter change, not a rewrite.
