# ARCEO SaaS — Build State Ledger

Durable, resumable state for the autonomous SaaS build. A fresh Fable session resumes
by reading this file, verifying the claimed state, and continuing from the first
unproven gate.

## Model boundary
- Builder/integrator: **Fable** (`claude-fable-5`). Sole implementer.
- Reviewer: **Codex Sol** (`gpt-5.6-sol`), read-only adversarial gates only. Never edits.

## Base and worktree
- Base SHA: `2b623a85fad329e8659d1cffb21fb1ed368918fc` (`origin/main`, tip merged rebrand + p09–p19 uplift).
- Feature branch: `saas/arceo-build`.
- Worktree: `/Users/hellohelloalbus/.config/superpowers/worktrees/heel/saas-arceo-build`.
- Rationale: the initial checkout (`codex/rebrand-arceo` @ `ef6b1bd`) was a **divergent duplicate rename, 45 commits behind** `origin/main` and missing the entire product-model/adapter uplift (`entitlements.py`, `economics.py`, `importers.py`, `openapi_import.py`, `control_simulator.py`, `bench.py`, `incident.py`, `modes.py`, …). Building on it would have been building on an obsolete branch. `origin/main` is the coherent upstream.

## Preservation decisions
- Untracked owner work in the original checkout (`launch/`, `docs/RESEARCH_LIBRARY_EXPANSION_PROMPT.md`) is **left untouched** in `/Users/hellohelloalbus/heel`. The new worktree is a separate directory; nothing there is moved, reset, or absorbed.
- No `git reset`, force-push, or branch deletion performed.

## Baseline verification (from base SHA)
- `python3 -m unittest discover -s tests -p 'test_*.py'` → **200 tests, OK** (Python 3.14.3, 2026-07-13).
- Pure-stdlib, zero runtime deps (DECISIONS D-001).

## Reusable core (verified present)
- `arceo/scope.py` — HMAC-signed, human-only `AuthorizationScope` (the safety spine). No write path over MCP/REST/agent.
- `arceo/entitlements.py` — entitlement *graph* over the tested ProductModel (NOT SaaS billing; distinct concern).
- `arceo/targets.py` — synthetic targets with planted ground truth.
- `arceo/store.py` — SQLite persistence: runs, findings, append-only hash-chained containment log.
- `arceo/rest.py`, `arceo/mcp_server.py` — loopback-only surfaces (must NOT be exposed as the SaaS API).
- `arceo/web_export.py` — static snapshot exporter (must NOT run against tenant/prod data).

## Phase status
| Phase | Description | Status |
|---|---|---|
| 0 | Inventory, reconcile upstream, worktree, baseline | **DONE** |
| 1 | Brand/open-core ADR, ICP, plans/prices, entitlement contract, architecture | in progress |
| 2 | SaaS foundation: schema, tenancy, auth, roles, API keys | pending |
| 3 | Job plane, target verification, signed scopes, safe adapters | pending |
| 4 | Usage ledger, quotas, billing lifecycle, reconciliation | pending |
| 5 | App UX, onboarding, live dashboard, integration surfaces | pending |
| 6 | Public website, pricing, enterprise, docs, lifecycle email, legal | pending |
| 7 | Security, privacy, admin, observability, support, runbooks | pending |
| 8 | IaC, CI/CD, staging, backup/restore/rollback | pending |
| 9 | Adversarial/integration/browser/load/recovery/black-box | pending |
| 10 | Staging rehearsal, launch docs, owner handoff | pending |

## Sol review gates — BLOCKED (mandatory independent review cannot run)
The Codex MCP transport is reachable (`mcp__codex__codex` returns structured responses), but the
mandated reviewer model **`gpt-5.6-sol` is unavailable on the installed Codex**. Exact error, returned
twice (initial + one retry) on 2026-07-13:

> 400 invalid_request_error: "The 'gpt-5.6-sol' model requires a newer version of Codex. Please
> upgrade to the latest app or CLI and try again."

Per §17 of the master prompt, I must NOT silently substitute another reviewer (e.g. gpt-5.2). No Sol
gate can be ratified until an owner upgrades the Codex CLI/app so `gpt-5.6-sol` resolves. This is a
true external blocker (see OWNER_ACTIONS #12). A **builder self-review** was performed instead and is
recorded in `docs/saas/SELF_REVIEW.md` — it is explicitly NOT the mandated independent review and does
not satisfy any gate.

| Gate | Scope | Thread ID | Disposition |
|---|---|---|---|
| 1 | Catalog, brand, architecture, open-core boundary | — | BLOCKED (Codex upgrade needed) |
| 2 | Tenancy, target verification, scope, worker isolation | — | BLOCKED |
| 3 | Billing, entitlement, usage ledger, free-tier liability | — | BLOCKED |
| 4 | Final diff, threat model, ops, website claims, launch readiness | — | BLOCKED |

## Open risks
- Full hosted deployment (live Postgres, Stripe live mode, deployed Next.js backend, workers, IaC-provisioned cloud) requires owner-only external credentials — tracked in `OWNER_ACTIONS.md`.

## True external blockers
See `docs/saas/OWNER_ACTIONS.md`.

## Exact next action
**BLOCKED on OWNER_ACTIONS #12** (Codex upgrade for `gpt-5.6-sol`) before any Sol gate can ratify.
Non-blocked implementation continues at **Phase 2**: hosted auth/session HTTP surface + `migrate`
module (SQLite↔Postgres) + `require()`-guarded control-plane API, then Phase 3 job plane + target
verification + egress guard. Resume by reading this ledger, re-running the verify command, and
continuing from Phase 2. Do NOT mark anything launch-ratified until Sol gates 1–4 pass.

## Fresh verification (2026-07-13, base + HEAD)
`python3 -m unittest discover -s tests -p 'test_*.py'` → **235 tests, OK** (Python 3.14.3).
