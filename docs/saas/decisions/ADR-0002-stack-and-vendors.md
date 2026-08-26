# ADR-0002 — Hosted stack and vendor selection

Status: Accepted (free-launch amendment 2026-08-04) · Date: 2026-07-13 · Decider: Fable (autonomous, delegated)

## Context
Solo founder, low ops burden, secure defaults, few vendors, strong local dev, hard free-tier cost
ceilings. Existing strengths: pure-stdlib Python engine + a Next.js control room. Full production
deploy needs owner credentials (blockers), so choices must have excellent *local* fidelity.

## Decisions (with rejected alternatives)
| Concern | Choice | Rejected | Why |
|---|---|---|---|
| Control-plane API | **Python (stdlib http.server-based, framework-light)** extending the existing engine | FastAPI, Django | Preserves zero-dep core philosophy for local dev; hosted layer may add a thin ASGI server behind a gate. Keeps one language for engine+control. |
| Relational store | **Single-node SQLite for free early access**; reconsider managed Postgres before horizontal or paid launch | MySQL, Mongo | The bounded launch has one process, a local durable volume, WAL, full sync, schema gates, backups, and a process lock. |
| Auth | **Vendor-native (Clerk or WorkOS/AuthKit)** for hosted; local dev uses a self-contained session/API-key module | Roll-your-own password auth | "Vendor-native auth over bespoke security" (spec §5). SSO/SCIM path via WorkOS for enterprise. |
| Billing | **Stripe** (see ADR-0003) | Paddle, Lemon Squeezy | Default candidate; test-clock + sandbox fidelity; customer portal. |
| Queue/workers | **SQLite-backed durable queues** for the deliberately single-node launch; reconsider a managed queue with horizontal scaling | Redis/Celery, Temporal | Fewer vendors and an executable ownership model for the bounded launch. |
| Secrets | Env + validated loader locally; **cloud secret manager** in prod | Committed config | Never commit secrets; rotation runbook. |
| Frontend | **Commercial Heel Cloud app at `apps/heel-cloud`**, with anonymous local review and browser-mediated account/device flows | Relabel existing `web/` | `web/` remains the Apache-2.0 snapshot control room; hosted source retains its commercial boundary. |
| Hosting | Cloudflare Worker plus private VPC/Tunnel binding to the single non-root control-plane container | A public Python origin | Exact public route allowlisting and defense-in-depth edge authorization preserve the local-first disclosure boundary. |

## Local-first principle
Everything runs locally with **zero external accounts** (SQLite, in-process queue, stub billing,
stub auth) so the whole funnel is testable and demoable offline. Prod adapters swap in behind
interfaces once owner supplies credentials. This makes the build turnkey without pretending
external accounts exist.

## As built for free early access (2026-08-04)

The production entrypoint requires a durable absolute SQLite path, strong peppers, a
canonical HTTPS origin, mandatory device auth, the edge secret, and free-launch billing.
It migrates before binding, locks the database to one process, runs WAL with full sync,
drains on signals, checkpoints on shutdown, and uses `DisabledBilling`.

The public Worker exposes only the exact account, device, project, and findings-continuity
surface over a private VPC service. PostgreSQL, managed queues, vendor identity, and Stripe
remain possible later adapters; they are not requirements or claimed integrations for the
bounded free launch.

## Reversibility
Store/queue/auth/billing are behind interfaces (`store.py` pattern already exists). Swapping a
vendor is an adapter change, not a rewrite.
