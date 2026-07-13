# ADR-0002 — Hosted stack and vendor selection

Status: Accepted · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

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
| Queue/workers | **Postgres-backed durable queue** (SKIP LOCKED) locally; managed (e.g. Cloud Tasks/SQS) in prod behind an interface | Redis/Celery, Temporal | Fewer vendors; Postgres queue is sufficient at launch scale and testable locally. |
| Secrets | Env + validated loader locally; **cloud secret manager** in prod | Committed config | Never commit secrets; rotation runbook. |
| Frontend | **Next.js** (existing `web/`), live authenticated backend replacing the static snapshot | SPA rewrite | Reuse existing control room; snapshot exporter demoted to demo-only. |
| Hosting | Owner-selected (Vercel for web + a container host for workers). Documented, not provisioned. | — | Requires owner accounts. |

## Local-first principle
Everything runs locally with **zero external accounts** (SQLite, in-process queue, stub billing,
stub auth) so the whole funnel is testable and demoable offline. Prod adapters swap in behind
interfaces once owner supplies credentials. This makes the build turnkey without pretending
external accounts exist.

## Reversibility
Store/queue/auth/billing are behind interfaces (`store.py` pattern already exists). Swapping a
vendor is an adapter change, not a rewrite.
