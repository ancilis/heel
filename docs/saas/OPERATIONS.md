# ARCEO Hosted — Operations (design + current state)

## Current runnable commands (local, zero external accounts)
- Bootstrap: `python3 -m venv .venv && . .venv/bin/activate` (core has zero deps; nothing to install).
- Verify (full): `python3 -m unittest discover -s tests -p 'test_*.py'` → 235 tests.
- SaaS core only: `python3 -m unittest tests.test_saas_core`.
- Engine demo: `make demo` (synthetic backtest + auth-gate proof over the MCP boundary).

## Planned operational surface (Phases 7–8, owner-credential-gated)
- **Observability:** structured logs, metrics, traces; error tracking (Sentry). Alerts: signup rate,
  checkout failures, webhook lag/failure, queue age, job failures, spend, abuse, tenant anomalies.
- **Health:** `/healthz` (liveness) and `/readyz` (DB + queue + billing reachability).
- **SLOs (proposed):** API availability 99.5%, webhook processing p95 < 30 s, run-start p95 < 60 s.
- **Backups:** managed Postgres PITR; monthly restore drill (runbook below). Object storage versioned.
- **Runbooks (to author in Phase 7):** incident, breach, billing-support, key-rotation, restore,
  target-abuse, kill-switch activation.
- **Kill switches:** global + per-tenant (design in ARCHITECTURE); wired to the entitlement service so a
  tripped switch denies `reserve()` at enqueue.

## Deployment commands (wrappers to build in Phase 8; require owner accounts)
- `make bootstrap` · `make verify` · `make deploy-staging` · `make smoke` · `make rollback`
- Migrations: `python3 -m arceo.saas.migrate up|down`.
- Billing sync: `python3 -m arceo.saas.billing sync` (creates Stripe Products/Prices from the catalog).

## Cost & capacity model
Per-workspace free-tier liability is bounded by the ledger ceilings (25 total / 5 verified runs, 1
verified target, concurrency 1) times per-run budget caps. A global circuit breaker bounds aggregate
free spend. Detailed numbers live in PRODUCT.md §cost-model once per-run budget constants are set in
Phase 3.

## Status
Only the local verify path is live today. All hosted operational tooling is designed and pending its
phase + owner credentials + Sol ratification.
